// Package alert tails the strip log and the WireGuard link state, and posts a
// redacted summary to an ntfy, Slack or Discord webhook. The pf alert command
// drives it. It never posts a token value.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/tailer"
)

const (
	defaultDebounce = 10 * time.Second
	webhookTimeout  = 2 * time.Second
	// retryAfter paces a retry of an undelivered line. The drain loop
	// polls five times a second, and an undelivered line holds the
	// checkpoint. Without a floor, a webhook that answers 429 immediately
	// would get the request again five times a second, for as long as it
	// continued to refuse. That changes a rate limit into a flood.
	retryAfter = 30 * time.Second
	// capWindow and defaultCapPosts are the overall budget of the webhook: a
	// maximum of this many posts an hour, whatever the host, rule or log.
	capWindow       = time.Hour
	defaultCapPosts = 30
	// queueMax bounds the posts that wait on the webhook. It is above both
	// hourly caps together, so it fills only when the webhook has refused for
	// some time.
	queueMax = 4 * defaultCapPosts
)

// errUndelivered stands for a post the operator did not get. The drain
// pass reports it; the row itself was recorded locally already.
var errUndelivered = errors.New("alert not delivered")

// errRefused is a post that the webhook refused for its body: status 400,
// 413 or 422. The same body gets the same answer each time, so a retry
// cannot deliver it. flush drops it.
var errRefused = fmt.Errorf("%w: the webhook refused the body", errUndelivered)

// The body limits of the sinks, measured after the escape of the sink.
// Discord refuses content over 2000 characters. A self-hosted ntfy refuses
// a message over 4096 bytes, and ntfy.sh changes it into an attachment.
// Slack takes more, but 3000 characters keeps a post short to read.
const (
	discordMax = 2000
	ntfyMax    = 4096
	slackMax   = 3000
	// postCut ends a post that PostMessage cut to the limit of its sink.
	postCut = " (cut)"
)

type Alerter struct {
	StripLog   string
	OffsetPath string
	// NoticeLog is the volume, dns_tunnel and dns_key rows of observe
	// (internal/observe notice). Alert tails it beside the strip log, with its
	// own checkpoint. When it is empty, alert does not tail it.
	NoticeLog        string
	NoticeOffsetPath string
	LastPath         string
	PolicyDirs       []string
	Client           *http.Client
	DebounceFor      time.Duration
	Poll             time.Duration
	Stdout           io.Writer
	Stderr           io.Writer
	Now              func() time.Time
	deb              Debounce
	// mu serialises handle: the two tails share the debounce, the cap,
	// the queue and retryAt.
	mu sync.Mutex
	// retryAt delays the next delivery attempt after a failed one.
	retryAt time.Time
	// CapPosts is the maximum number of posts in one hour, across both logs. 0
	// is defaultCapPosts, and a negative value is no cap. See webhookCap.
	CapPosts int
	cap      webhookCap
	// queue is what waits on the webhook, oldest first. A row is recorded
	// locally (alert.last, the console line) and checkpointed immediately when
	// it is read. Its post waits here. So a webhook that refuses or hangs never
	// delays the logs or the other tail.
	queue []pending
	seq   uint64
	// postMu is held by the tail that posts. The other tail skips its flush,
	// and does not wait on the network.
	postMu sync.Mutex
	// Pressure, when it is set, watches memory and CPU pressure beside the
	// tails of Run. It posts through its own sender.
	Pressure *Pressure
	// Digest, when it is set, adds the Blocks rows of the notice log into a
	// digest of blocked requests, and posts it a maximum of one time in
	// each window (digest.go). When it is nil, a Blocks row is only a
	// console line.
	Digest *Digest
}

type pending struct {
	id   uint64
	msg  string
	kind string
	// keep marks a post that overflow drops last: a canary, a
	// credential, a key.
	keep   bool
	canary bool
}

// webhookCap is the overall ceiling above the per-incident debounce. The
// debounce suppresses a repeat of one incident. It does nothing for an
// agent that walks hosts or rules, because each is a new key, and each of
// those was a post. The phone buzzed each ten seconds for as long as the
// loop ran. Then the operator muted the channel, and with it the one
// important alert. Or ntfy or Slack rate-limited the webhook and dropped
// that alert for them. So a fixed window, opened by its first post, carries
// a maximum of CapPosts. Past that, a row is suppressed from the webhook
// only. The log line, the console line and alert.last are written as
// always. When the window rolls, one post tells how many were suppressed,
// and of what kind. A canary row is never suppressed (docs/fence.md
// promises that it always arrives). Credential and key rows (keyAlert) have
// their own budget beside the general one. So thirty junk tunnel notices
// cannot spend the hour that a leaked key needed.
type webhookCap struct {
	start      time.Time
	posted     int
	keyPosted  int
	suppressed int
	by         map[string]int
}

// after gives the window that starts when the summary of snap is posted.
// A suppression that occurs while the summary is out belongs to the next
// summary.
func (c webhookCap) after(snap webhookCap, start time.Time) webhookCap {
	rest := webhookCap{start: start, posted: 1, suppressed: c.suppressed - snap.suppressed}
	for k, n := range c.by {
		if n -= snap.by[k]; n > 0 {
			if rest.by == nil {
				rest.by = map[string]int{}
			}
			rest.by[k] = n
		}
	}
	return rest
}

func (a *Alerter) capPosts() int {
	if a.CapPosts == 0 {
		return defaultCapPosts
	}
	return a.CapPosts
}

// capFull reports whether this window has no post left for the row's
// budget. Called under mu.
func (a *Alerter) capFull(key bool) bool {
	n := a.cap.posted
	if key {
		n = a.cap.keyPosted
	}
	return a.capPosts() > 0 && !a.cap.start.IsZero() && n >= a.capPosts()
}

// capPosted counts one post against its budget. It opens a window if no
// window is open. Called under mu.
func (a *Alerter) capPosted(key bool) {
	if a.cap.start.IsZero() {
		a.cap.start = a.clock()
	}
	if key {
		a.cap.keyPosted++
	} else {
		a.cap.posted++
	}
}

// suppress counts one row the webhook will not carry. Called under mu.
func (a *Alerter) suppress(kind string) {
	a.cap.suppressed++
	if a.cap.by == nil {
		a.cap.by = map[string]int{}
	}
	a.cap.by[kind]++
}

func (a *Alerter) capExpired() bool {
	return !a.cap.start.IsZero() && a.clock().Sub(a.cap.start) >= capWindow
}

// capRollQuiet closes a window that has run its hour with nothing to
// report. A window that suppressed something stays open, and full, until
// flush has posted its summary. A roll before that would lose the one
// message that says that alerts were missed. Called under mu.
func (a *Alerter) capRollQuiet() {
	if a.capExpired() && a.cap.suppressed == 0 {
		a.cap = webhookCap{}
	}
}

// summary is the post that tells what a window suppressed, by kind.
func (a *Alerter) summary() string {
	n := a.cap.suppressed
	kinds := make([]string, 0, len(a.cap.by))
	for k := range a.cap.by {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool {
		if a.cap.by[kinds[i]] != a.cap.by[kinds[j]] {
			return a.cap.by[kinds[i]] > a.cap.by[kinds[j]]
		}
		return kinds[i] < kinds[j]
	})
	parts := make([]string, len(kinds))
	for i, k := range kinds {
		parts[i] = fmt.Sprintf("%s %d", k, a.cap.by[k])
	}
	what := ""
	if len(parts) > 0 {
		what = " (" + strings.Join(parts, ", ") + ")"
	}
	// Both budgets are capPosts (capFull). So the code builds the sentence from
	// it, not from a number written into the text.
	c := a.capPosts()
	return fmt.Sprintf("%d alert%s suppressed in the last hour%s: the webhook takes at most %d ordinary posts and %d credential or key posts an hour, and never holds back a canary. Every one is in the logs (pf alert show).", n, plural(n), what, c, c)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Debounce suppresses a repeat of an incident that the operator already
// got. It remembers many incidents, not one. A single slot is not a
// debounce at all when two incidents interleave: each new key evicted the
// last. So two hosts in alternation posted on each line, while a run of one
// host correctly posted once. An agent causes the input to the table, so
// the table is bounded as internal/www bounds its ledger. Expired entries
// go first. If the table is still full after that, it is dropped whole. It
// is not allowed to climb.
//
// The threat comes first in the key, because it is the one distinction
// that must never collapse. The broker writes refusals with no rule. So a
// canary refusal and an ordinary refusal on the same host and where shared
// a key. The ordinary one then silenced the canary for ten seconds. That is
// exactly the alert that docs/fence.md promises will always arrive.
type Debounce struct {
	Window time.Duration
	Now    func() time.Time
	at     map[string]time.Time
}

const debounceMax = 512

func (d *Debounce) OK(threat, rule, where, host string) bool {
	win := d.Window
	if win == 0 {
		win = defaultDebounce
	}
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	key := threat + "\x00" + rule + "\x00" + where + "\x00" + host
	if d.at == nil {
		d.at = map[string]time.Time{}
	}
	if at, ok := d.at[key]; ok && now.Sub(at) < win {
		return false
	}
	if len(d.at) >= debounceMax {
		for k, at := range d.at {
			if now.Sub(at) >= win {
				delete(d.at, k)
			}
		}
		if len(d.at) >= debounceMax {
			d.at = map[string]time.Time{}
		}
	}
	d.at[key] = now
	return true
}

func Defaults() *Alerter {
	return &Alerter{
		StripLog:         "/var/log/pi-fortress/strip.jsonl",
		OffsetPath:       "/var/lib/pi-fortress/alert.offset",
		NoticeLog:        "/var/log/pi-fortress/notice.jsonl",
		NoticeOffsetPath: "/var/lib/pi-fortress/alert-notice.offset",
		LastPath:         "/var/lib/pi-fortress/alert.last",
		PolicyDirs:       []string{"/vagrant/vm/policy", "/etc/pi-fortress"},
	}
}

func (a *Alerter) out() io.Writer {
	if a == nil {
		return os.Stdout
	}
	return tailer.Out(a.Stdout)
}

func (a *Alerter) errw() io.Writer {
	if a != nil && a.Stderr != nil {
		return a.Stderr
	}
	return os.Stderr
}

func (a *Alerter) client() *http.Client {
	if a != nil && a.Client != nil {
		return a.Client
	}
	return &http.Client{Timeout: webhookTimeout}
}

func Summarize(event map[string]any) string {
	if tailer.Field(event, "ev", "") == jsonl.StripSuppressedEv {
		return stripSuppressedLine(event)
	}
	switch field(event, "threat", "") {
	case jsonl.BlocksThreat:
		return blocksLine(event)
	case "canary":
		return "CANARY " + summarize(event)
	case "slot_budget":
		return budgetLine(event)
	case "slot_expiry":
		return expiryLine(event)
	case "volume", "dns_tunnel", "dns_key":
		return noticeLine(event)
	}
	return summarize(event)
}

// stripSuppressedLine is the strip log writer report that it dropped the
// strip and refusal rows of one client over the budget of that client
// (internal/jsonl). Nothing got through: each of those requests was still
// stripped or refused. Only its row was not written. The row has the shape
// of the strip row, so each reader parses it. That is why it read as
// "STRIP suppressed in suppressed -> *" until it got its own line.
func stripSuppressedLine(event map[string]any) string {
	return "LOG BUDGET " + field(event, "client_ip", "?") + ": " + count(event, "count") +
		" strip or refusal rows not logged, over the per-client budget (" +
		strconv.FormatFloat(jsonl.StripRowRate, 'f', -1, 64) + " a second, " + strconv.Itoa(jsonl.StripRowBurst) +
		" at once) since the last report. Each request was still stripped or refused; only its row was dropped."
}

// noticeLine is something that observe noticed and nothing stopped
// (internal/observe notice): a bulk upload, or a run of query names with
// the shape of a payload.
func noticeLine(event map[string]any) string {
	what := "BULK UPLOAD"
	switch field(event, "threat", "") {
	case "dns_tunnel":
		what = "DNS TUNNEL?"
	case "dns_key":
		what = "KEY IN A DNS NAME"
	}
	return what + " " + field(event, "client_ip", "?") + " (" + field(event, "where", "?") + ") -> " +
		field(event, "host", "?") + ": " + field(event, "detail", "?")
}

// budgetLine is a crossing of a per-slot hourly ceiling
// (internal/broker/budget.go). It gets its own sentence, because it is the
// one row here that is not a strip and not a refusal. Nothing was blocked:
// a rate was reached. The operator must decide if that rate is their own
// agent at work, or their own agent in a loop. A stop that the broker
// could not apply says so. To read "stop" and believe that the spend ended
// would be the worse mistake.
func budgetLine(event map[string]any) string {
	verb := "WARN"
	switch rule, _, _ := strings.Cut(field(event, "rule", ""), ":"); rule {
	case "slot_budget_stop":
		verb = "STOP"
	case "slot_budget_stop_failed":
		verb = "STOP FAILED"
	}
	return "SLOT BUDGET " + verb + " slot " + field(event, "slot", "?") + ": " +
		count(event, "count") + " " + field(event, "where", "?") + " in the last hour, limit " +
		count(event, "limit") + " -> " + field(event, "host", "?")
}

// expiryLine is a slot that is near or past its deadline
// (internal/broker/expiry.go). It ends with the command that fixes it,
// because a renewal is all that the operator has to do.
func expiryLine(event map[string]any) string {
	slot := field(event, "slot", "?")
	head := "SLOT EXPIRES in " + count(event, "count") + " days"
	if rule, _, _ := strings.Cut(field(event, "rule", ""), ":"); rule == "slot_expired" {
		head = "SLOT EXPIRED, placeholder now refused"
	}
	return head + ": slot " + slot + " (" + field(event, "where", "?") + "). Renew: sudo pf enroll renew --slot " + slot + " --expires 90d"
}

// count reads a number from a row. Each JSON number arrives as a float64.
// A direct print of a float64 changes a byte count into scientific
// notation.
func count(event map[string]any, key string) string {
	f, ok := event[key].(float64)
	if !ok {
		return "?"
	}
	return strconv.FormatInt(int64(f), 10)
}

func summarize(event map[string]any) string {
	// A refusal row with where "audit" is a check in audit mode: the
	// connection went ahead. The post must not say that it was refused.
	if field(event, "ev", "") == refusedEv && field(event, "where", "") == "audit" {
		return "AUDIT " + field(event, "cause", "?") + " (" + field(event, "kind", "?") + ") -> " +
			field(event, "host", "?") + " " + field(event, "dest_ip", "?") + " (connection allowed)"
	}
	if field(event, "ev", "") == refusedEv {
		return "REFUSED " + field(event, "cause", "?") + " slot " + field(event, "slot", "?") +
			" (" + field(event, "kind", "?") + ") -> " + field(event, "host", "?")
	}
	return "STRIP " + field(event, "rule", "?") + " in " + field(event, "where", "?") + " -> " + field(event, "host", "?")
}

const refusedEv = "substitution_refused"

// field is the value of a row as it may be printed or posted. Each field
// of these rows is text that an agent or a device influenced (a host, a
// zone, a path segment). So no part of it reaches the console, the journal
// or a webhook without tailer.Printable.
func field(event map[string]any, key, empty string) string {
	return tailer.Printable(tailer.Field(event, key, empty))
}

// kindOf names a row in the suppressed summary.
func kindOf(event map[string]any) string {
	if t := field(event, "threat", ""); t != "" {
		return t
	}
	if tailer.Field(event, "ev", "") == jsonl.StripSuppressedEv {
		return jsonl.StripSuppressedEv
	}
	if tailer.Field(event, "ev", "") == refusedEv {
		return "refused"
	}
	return "strip"
}

// keyAlert is a row about a credential or a key: a stripped literal slot
// secret, a refusal that the broker marked to alert, a key in a DNS name, a
// bulk upload. These rows have their own hourly budget (webhookCap).
//
// An eyeball row is not about a key. The broker marks one to alert for
// each new name and ASN pair, and the agent selects the names. So
// those rows go on the ordinary budget, and a run of them cannot use the
// posts that a stripped secret needs.
func keyAlert(event map[string]any) bool {
	switch tailer.Field(event, "threat", "") {
	case "dns_key", "volume":
		return true
	}
	if tailer.Field(event, "ev", "") == refusedEv {
		return tailer.Field(event, "cause", "") != eyeballCause
	}
	return strings.HasPrefix(tailer.Field(event, "rule", ""), "secret:")
}

// eyeballCause is the cause of an eyeball row (internal/broker
// CauseEyeball).
const eyeballCause = "eyeball_network"

// postable decides what reaches the webhook. A strip is the incident by
// definition: the agent already had the secret. A refusal is not always an
// incident. A sealed store refuses all that an agent retries, and only the
// broker knows which of those is the first. The broker marks that row. The
// unmarked rows stay in the log, and do not go to the webhook.
//
// A slot_budget row is neither, and it posts. The broker writes one only
// when a slot crosses a line, and it does its own debounce. So each of
// those rows is a thing that the operator asked to be woken for.
func postable(event map[string]any) bool {
	if tailer.Field(event, "ev", "") != refusedEv {
		return true
	}
	alert, _ := event["alert"].(bool)
	return alert
}

func LoadURL(dirs []string) string {
	for _, dir := range dirs {
		raw, err := os.ReadFile(filepath.Join(dir, "alert.url"))
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			if i := strings.Index(line, "#"); i >= 0 {
				line = line[:i]
			}
			line = strings.TrimSpace(line)
			if line != "" {
				return line
			}
		}
	}
	return ""
}

func slack(url string) bool { return strings.Contains(url, "hooks.slack.com") }

func discord(url string) bool {
	return strings.Contains(url, "discord.com/api/webhooks") ||
		strings.Contains(url, "discordapp.com/api/webhooks")
}

// slackEscape applies the escape rules of Slack: &, < and > are all of its
// control syntax. So <https://evil.example|rotate-key-now>, <!channel> and
// <@U123> all arrive as text. The post also sets mrkdwn off, so * _ ~ and
// backticks have no effect.
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace

// discordEscape backslash-escapes the markdown of Discord, so
// [x](https://evil) is not a masked link. It breaks @everyone and @here
// with a zero-width space. The post also allows no mentions at all.
var discordEscape = strings.NewReplacer(
	`\`, `\\`, "*", `\*`, "_", `\_`, "~", `\~`, "`", "\\`", "|", `\|`,
	"[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`, "<", `\<`, ">", `\>`, "#", `\#`,
	"@", "@\u200b",
).Replace

// endpoint is the part of a webhook URL that may be said out loud. The URL
// is the credential: the path or the query carries an ntfy topic, a Slack
// services path, or a Discord webhook id and token. A reader who reads one
// from the journal can post to the channel of the operator. Scheme and
// host name the endpoint that went quiet. That is all that a diagnosis
// needs.
func endpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(webhook)"
	}
	return u.Scheme + "://" + u.Host
}

// postFailure describes a failed delivery, and does not quote the URL.
// http.Client.Do reports each transport fault as a *url.Error, and its
// Error method prints the full request URL. So the obvious "%v" copied the
// webhook credential of the operator to stderr. vm/pi/alert.service sets
// no StandardError, so stderr is journald. journald is permanent, and each
// diagnostic export after that collects it. A flaky link was enough to
// cause this; no attacker was necessary. The wrapped cause is repeated only
// when it does not itself quote the URL, because a few causes do.
func postFailure(raw string, err error) string {
	var ue *url.Error
	if !errors.As(err, &ue) {
		if leaks(err.Error(), raw) {
			return endpoint(raw) + ": request error"
		}
		return endpoint(raw) + ": " + err.Error()
	}
	cause := "transport error"
	switch {
	case ue.Timeout():
		cause = "timeout"
	case errors.Is(ue.Err, context.Canceled):
		cause = "canceled"
	case ue.Err != nil && !leaks(ue.Err.Error(), raw, ue.URL):
		cause = ue.Err.Error()
	}
	return endpoint(raw) + ": " + cause
}

// leaks reports whether text repeats any secret-bearing part of the URLs
// that it came from. A match of the full URL is not enough alone: a cause
// can name only the path, and for Slack and Discord the path is the full
// secret.
func leaks(text string, raws ...string) bool {
	for _, raw := range raws {
		if raw == "" {
			continue
		}
		if strings.Contains(text, raw) {
			return true
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if p := strings.Trim(u.EscapedPath(), "/"); p != "" && strings.Contains(text, p) {
			return true
		}
		if u.RawQuery != "" && strings.Contains(text, u.RawQuery) {
			return true
		}
	}
	return false
}

func (a *Alerter) PostWebhook(hook string, event map[string]any) error {
	return a.PostMessage(hook, Summarize(event))
}

// PostMessage returns whether the operator got the message. Nothing to
// send is not a failure. A webhook that refused or never answered is a
// failure. The caller uses that to decide if the event may be checkpointed.
// A message over the body limit of the sink is cut to fit (fit), so the
// sink does not refuse it for its size.
func (a *Alerter) PostMessage(hook, msg string) error {
	if hook == "" || msg == "" {
		return nil
	}
	headers := map[string]string{
		"Title":      "pi-fortress",
		"Priority":   "high",
		"Tags":       "warning,key",
		"User-Agent": "pi-fortress-alert",
	}
	// ntfy shows a text/plain body as text (Markdown only with a
	// Markdown header, which is never sent). So it needs no escape
	// beyond the control runes that Printable already removed. ntfy
	// changes a body that is not UTF-8 into an attachment, so an invalid
	// byte becomes U+FFFD.
	msg = strings.ToValidUTF8(tailer.Printable(msg), "\uFFFD")
	var body []byte
	switch {
	case slack(hook):
		body, _ = json.Marshal(map[string]any{"text": fit(msg, slackEscape, utf16Len, slackMax), "mrkdwn": false})
		headers["Content-Type"] = "application/json"
	case discord(hook):
		body, _ = json.Marshal(map[string]any{"content": fit(msg, discordEscape, utf16Len, discordMax), "allowed_mentions": map[string]any{"parse": []string{}}})
		headers["Content-Type"] = "application/json"
	default:
		body = []byte(fit(msg, func(s string) string { return s }, func(s string) int { return len(s) }, ntfyMax))
		headers["Content-Type"] = "text/plain"
	}
	req, err := http.NewRequest(http.MethodPost, hook, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(a.errw(), "alert webhook failed: %s\n", postFailure(hook, err))
		return errUndelivered
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.client().Do(req)
	if err != nil {
		fmt.Fprintf(a.errw(), "alert webhook failed: %s\n", postFailure(hook, err))
		return errUndelivered
	}
	_, _ = io.CopyN(io.Discard, resp.Body, 64)
	_ = resp.Body.Close()
	// A 429 from ntfy or a 500 from Slack means that the operator never got
	// the alert. Without a check, it looks the same as a delivery, so an alert
	// that never arrived was recorded as sent. Report it as loudly as a
	// dropped connection.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(a.errw(), "alert webhook failed: %s: status %d\n", endpoint(hook), resp.StatusCode)
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
			return errRefused
		}
		return errUndelivered
	}
	return nil
}

// fit gives esc(msg) at a maximum size of limit. When it is larger, fit
// cuts msg before the escape, at a rune boundary, and adds postCut. Each
// escape here changes one rune at a time, so a cut is never inside an
// escape sequence.
func fit(msg string, esc func(string) string, size func(string) int, limit int) string {
	out := esc(msg)
	if size(out) <= limit {
		return out
	}
	mark := esc(postCut)
	room, n := limit-size(mark), 0
	for i, r := range msg {
		if n += size(esc(string(r))); n > room {
			return esc(msg[:i]) + mark
		}
	}
	return out
}

// utf16Len counts the characters of s as Discord and Slack can count them.
// A rune above U+FFFF counts as two. Thus the count is never less than the
// count of the sink.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

func (a *Alerter) saveLast(event map[string]any) error {
	if a.LastPath == "" {
		return nil
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.LastPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(a.LastPath, append(raw, '\n'), 0644)
}

// handle records a row and queues its post. The local record comes first,
// always: alert.last and the console line are written immediately when the
// row is read. The checkpoint moves past the row, whatever the webhook
// does. The post itself waits in the queue for flush.
func (a *Alerter) handle(line, url string) error { return a.handleFrom(line, url, false) }

// handleFrom is handle with the log that the line came from. Only pf
// observe writes the notice log. So only a Blocks row from that log goes
// into the digest.
func (a *Alerter) handleFrom(line, url string, notice bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	raw := strings.TrimSpace(line)
	if raw == "" {
		return nil
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(raw), &event); err != nil || event == nil {
		return nil
	}
	// A Blocks row is a count for the digest, not an alert. It does not
	// replace alert.last, and it never posts alone.
	if tailer.Field(event, "threat", "") == jsonl.BlocksThreat {
		fmt.Fprintln(a.out(), Summarize(event))
		if row, ok := digestRow(raw); ok && notice && url != "" && a.Digest != nil {
			a.Digest.add(row, a.clock())
		}
		return nil
	}
	if a.deb.Now == nil && a.Now != nil {
		a.deb.Now = a.Now
	}
	if a.deb.Window == 0 {
		a.deb.Window = a.DebounceFor
	}
	_ = a.saveLast(event)
	msg := Summarize(event)
	fmt.Fprintln(a.out(), msg)
	threat := tailer.Field(event, "threat", "")
	host := tailer.Field(event, "host", "")
	// The summary rows of the writer all have host "*". One sweep writes one
	// per client at once. With "*" as the key, only the first would post.
	if tailer.Field(event, "ev", "") == jsonl.StripSuppressedEv {
		host = tailer.Field(event, "client_ip", "")
	}
	canary := threat == "canary"
	if url == "" || !postable(event) || (!canary && !a.deb.OK(threat, tailer.Field(event, "rule", ""), tailer.Field(event, "where", ""), host)) {
		return nil
	}
	a.capRollQuiet()
	kind, key := kindOf(event), keyAlert(event)
	if !canary {
		if a.capFull(key) {
			a.suppress(kind)
			return nil
		}
		a.capPosted(key)
	}
	a.enqueue(pending{msg: msg, kind: kind, keep: canary || key, canary: canary})
	return nil
}

// enqueue adds a post. To make room, it drops the oldest ordinary post. If
// there is none, it drops the oldest key post. A canary post goes only
// when the queue holds canary posts only and p is a canary post too: then
// the oldest canary post goes. A post that is not a canary never makes a
// canary post go: p goes instead. Each drop counts as suppressed, so the
// summary still tells that it was missed. Called under mu.
func (a *Alerter) enqueue(p pending) {
	if len(a.queue) >= queueMax {
		i := slices.IndexFunc(a.queue, func(q pending) bool { return !q.keep })
		if i < 0 {
			i = slices.IndexFunc(a.queue, func(q pending) bool { return !q.canary })
		}
		if i < 0 && !p.canary {
			a.dropped(p.kind)
			return
		}
		if i < 0 {
			i = 0
		}
		a.dropped(a.queue[i].kind)
		a.queue = slices.Delete(a.queue, i, i+1)
	}
	a.seq++
	p.id = a.seq
	a.queue = append(a.queue, p)
}

// dropped counts a post that overflow removed. It opens a window if no
// window is open, so that a summary reports the drop. Called under mu.
func (a *Alerter) dropped(kind string) {
	a.suppress(kind)
	if a.cap.start.IsZero() {
		a.cap.start = a.clock()
	}
}

// next is what flush posts now: the oldest canary post, then the summary
// of a window when its hour is up, else the oldest queued post. Nothing
// while the retry floor of a failed post holds. A canary goes first,
// because docs/fence.md promises that it arrives, and older posts must not
// delay it. Called under mu.
func (a *Alerter) next() (p pending, summary bool, ok bool) {
	if a.holdingOff() {
		return pending{}, false, false
	}
	if i := slices.IndexFunc(a.queue, func(q pending) bool { return q.canary }); i >= 0 {
		return a.queue[i], false, true
	}
	if a.capExpired() {
		if a.cap.suppressed > 0 {
			return pending{msg: a.summary()}, true, true
		}
		a.cap = webhookCap{}
	}
	if len(a.queue) == 0 {
		return pending{}, false, false
	}
	return a.queue[0], false, true
}

// flush posts what is queued, in the order of next, until the queue is
// empty or a post fails. A failure delays the next attempt for retryAfter,
// and keeps the post at the head. A post that the webhook refused for its
// body (errRefused) is not a failure of the webhook: flush drops it, counts
// it as suppressed for the summary, and continues. A retry of that post
// cannot succeed, and it would hold each post after it. The summary is not
// dropped: it is the one message that says that alerts were missed, and
// only pf writes its text, cut to fit. So a refusal of it is a problem of
// the webhook, and it gets the retry. flush never touches the network
// under mu. So handle (and with it the other tail) continues while a post
// is out.
func (a *Alerter) flush(url string) error {
	if url == "" || !a.postMu.TryLock() {
		return nil
	}
	defer a.postMu.Unlock()
	for {
		a.mu.Lock()
		p, summary, ok := a.next()
		var snap webhookCap
		if summary {
			// A copy of by, not the live map: handle adds to the live map
			// while the post is out, and after subtracts snap from it.
			snap = a.cap
			snap.by = maps.Clone(a.cap.by)
		}
		a.mu.Unlock()
		if !ok {
			return nil
		}
		err := a.PostMessage(url, p.msg)
		a.mu.Lock()
		if err != nil && (summary || !errors.Is(err, errRefused)) {
			a.retryAt = a.clock().Add(retryAfter)
			a.mu.Unlock()
			return err
		}
		a.retryAt = time.Time{}
		if err != nil {
			fmt.Fprintln(a.errw(), "alert post dropped: the webhook refused its body; the next summary counts it")
		}
		if summary {
			a.cap = a.cap.after(snap, a.clock())
		} else if i := slices.IndexFunc(a.queue, func(q pending) bool { return q.id == p.id }); i >= 0 {
			a.queue = slices.Delete(a.queue, i, i+1)
			if err != nil {
				a.dropped(p.kind)
			}
		}
		a.mu.Unlock()
	}
}

func (a *Alerter) clock() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Alerter) holdingOff() bool {
	return !a.retryAt.IsZero() && a.clock().Before(a.retryAt)
}

func summarizeLine(line string) string {
	var event map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(line)), &event) == nil && event != nil {
		return Summarize(event) + "\n"
	}
	return line
}

func (a *Alerter) tail() *tailer.Tail { return a.tailOf(false) }

// tailOf is the tail of the strip log, or with notice set, the sink of
// the notice log. The caller sets the paths of the notice log.
func (a *Alerter) tailOf(notice bool) *tailer.Tail {
	var url string
	return &tailer.Tail{
		Path:       a.StripLog,
		OffsetPath: a.OffsetPath,
		ShowPath:   a.StripLog,
		LastPath:   a.LastPath,
		Empty:      "(no strips yet)",
		Poll:       a.Poll,
		Stdout:     a.Stdout,
		Stderr:     a.Stderr,
		Deliver: func() func(line string) error {
			url = LoadURL(a.PolicyDirs)
			return func(line string) error { return a.handleFrom(line, url, notice) }
		},
		After: func() error {
			a.digestTick(url)
			return a.flush(url)
		},
		Line: summarizeLine,
	}
}

func (a *Alerter) Drain(fromEnd bool) error { return a.tail().Drain(fromEnd) }

func (a *Alerter) Show() int { return a.tail().Show() }

func (a *Alerter) Once() int { return a.tail().Once() }

// noticeTail is the second log. It keeps no last-event file of its own:
// handle writes LastPath for both.
func (a *Alerter) noticeTail() *tailer.Tail {
	t := a.tailOf(true)
	t.Path, t.OffsetPath, t.ShowPath = a.NoticeLog, a.NoticeOffsetPath, a.NoticeLog
	return t
}

// digestTick closes the digest window when its time is up, and queues its
// post. The post goes through the queue, so a failed post gets the same
// retry as the others. It does not use the hourly cap: the digest is a
// maximum of one post in each window already.
func (a *Alerter) digestTick(url string) {
	if a.Digest == nil || url == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if msg := a.Digest.due(a.clock()); msg != "" {
		fmt.Fprintln(a.out(), msg)
		a.enqueue(pending{msg: msg, kind: jsonl.BlocksThreat, keep: true})
	}
}

func (a *Alerter) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	if p := a.Pressure; p != nil {
		if p.Stdout == nil {
			p.Stdout = a.out()
		}
		if p.Stderr == nil {
			p.Stderr = a.errw()
		}
		s := newSender(p.Stdout, p.Stderr, func() string { return LoadURL(a.PolicyDirs) })
		wg.Add(2)
		go func() { defer wg.Done(); s.run(ctx) }()
		go func() { defer wg.Done(); p.Run(ctx, s.put) }()
	}
	if a.NoticeLog == "" {
		return a.tail().Run(ctx)
	}
	done := make(chan error, 1)
	go func() { done <- a.noticeTail().Run(ctx) }()
	err := a.tail().Run(ctx)
	if nerr := <-done; err == nil {
		err = nerr
	}
	return err
}

func (a *Alerter) Watch(ctx context.Context) error { return a.tail().Watch(ctx) }
