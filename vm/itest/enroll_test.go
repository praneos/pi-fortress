//go:build vagrant

package itest

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// enrollTests walks the enrolment that the user guide documents, end to
// end on the lab: the agent commands of getting_started §2, then mint,
// list, claim, revoke (§3, §4, "Revoking"), and the "claim code" claim of
// the faq.
//
// The subtests run in order on purpose: the claim needs the slot that the
// mint made, and the revoke deletes it. The state is a slot that belongs
// to this group. Thus a run does not depend on what an earlier run left.
// The codes are new for this run. That keeps the once-only subtest
// independent of earlier runs of this group.
//
// None of it needs a real Anthropic credential: the minted values are
// sentinels that the echo of the lab reflects back.
func enrollTests(t *testing.T) {
	piIP := netenv(t)["PI_IP"]
	if piIP == "" {
		piIP = "10.77.0.1"
	}

	// The commands of getting_started §2, in the order of the doc. Each
	// one asserts the result that its comment promises. The first two have
	// no comment: their promise is that they exit clean, with both hashes
	// read from the gateway in the documented way. That is the form that a
	// reader copies.
	t.Run("the documented setup lines enrol the agent against the gateway", func(t *testing.T) {
		setup, ca := wwwSHA256(t, "setup.sh"), wwwSHA256(t, "ca.pem")
		out, err := ssh(t, 3*time.Minute, "agent", "curl -fsSo /tmp/pf-setup.sh http://"+piIP+"/setup.sh && echo '"+setup+"  /tmp/pf-setup.sh' | sha256sum -c && sudo bash /tmp/pf-setup.sh "+piIP+" "+ca)
		if err != nil || !contains(out, "pi-fortress setup: done") {
			t.Fatalf("%v\n%s", err, out)
		}
	})
	t.Run("dig example.com resolves", func(t *testing.T) {
		out := agent(t, "dig +short +time=3 +tries=2 example.com")
		if firstIPv4(out) == "" {
			t.Fatalf("no A record for example.com from the agent's pinned resolver:\n%s", out)
		}
	})
	t.Run("https example.com answers 200 through the gateway", func(t *testing.T) {
		out, err := ssh(t, 30*time.Second, "agent", "curl -I -sS --max-time 10 https://example.com")
		if err != nil || !lineWith(out, "HTTP/", " 200") {
			t.Fatalf("%v\n%s", err, out)
		}
	})
	t.Run("the blocklist canary resolves to 0.0.0.0", func(t *testing.T) {
		out := agent(t, "dig +short +time=3 +tries=2 pi-fortress-block.test")
		var got []string
		for line := range strings.SplitSeq(out, "\n") {
			if line = strings.TrimSpace(line); ipv4(line) {
				got = append(got, line)
			}
		}
		// Exactly the sinkhole answer: a canary that also carries a real
		// address is a blocklist that is not blocking.
		if len(got) != 1 || got[0] != "0.0.0.0" {
			t.Fatalf("want one 0.0.0.0, got %v\n%s", got, out)
		}
	})
	t.Run("https to a direct IP times out", func(t *testing.T) {
		mustFailOn(t, "agent", "curl -sS --max-time 5 -o /dev/null https://192.0.2.1")
	})
	t.Run("https to a public DoH resolver times out", func(t *testing.T) {
		mustFailOn(t, "agent", "curl -sS --max-time 5 -o /dev/null https://1.1.1.1")
	})

	// Sentinels, minted in the documented way. They are the full purpose of
	// the file checks below. Each assertion that the agent has no live token
	// looks for these exact strings and also for the sk-ant prefix. Thus a
	// leak of the value of this slot cannot hide behind a different shape.
	oat := "sk-ant-oat01-" + strings.Repeat("E", 64)
	ort := "sk-ant-ort01-" + strings.Repeat("F", 64)

	// No seedLabSecrets here. It rewrites the full store from a backup that
	// the secrets group owns. This group needs one slot of its own, not a
	// known inventory. A mint appends. The cleanup deletes exactly what was
	// appended, so the store stays as it was found.
	mintOut := pi(t, "printf '%s\\n%s\\n' '"+oat+"' '"+ort+"' | sudo pf enroll mint --kind CLAUDE --stdin")
	slot := field(mintOut, "slot")
	if len(slot) != 16 {
		t.Fatalf("no slot from mint:\n%s", mintOut)
	}
	phOAT := "pf_" + slot + "_CLAUDE_OAT"
	phORT := "pf_" + slot + "_CLAUDE_ORT"
	var codes []string
	t.Cleanup(func() {
		// The slot first: a run that fails before the revoke subtest must
		// not leave a live sentinel in the store for the next run. The
		// delete may fail, because the revoke subtest possibly did it
		// already. The paste file is on the synced folder. Otherwise it
		// would show as an untracked file in the repo.
		_, _ = ssh(t, 30*time.Second, "pi", "sudo pf enroll delete --slot "+slot+" || true")
		_, _ = ssh(t, 20*time.Second, "pi", "sudo rm -f /vagrant/vm/policy/generated/agent-credentials-"+slot+".json /etc/pi-fortress/agent-credentials-"+slot+".json")
		for _, c := range codes {
			_, _ = ssh(t, 20*time.Second, "pi", "sudo rm -f /var/lib/pi-fortress/www/claims/"+c+".json /var/lib/pi-fortress/www/claims/"+c+".redeemed")
		}
	})

	t.Run("mint prints a slot and placeholders and never the tokens it was given", func(t *testing.T) {
		if !contains(mintOut, phOAT) || !contains(mintOut, phORT) {
			t.Fatalf("mint printed no placeholders:\n%s", mintOut)
		}
		if contains(mintOut, oat) || contains(mintOut, ort) || contains(mintOut, "sk-ant") {
			t.Fatalf("mint echoed a live token back at the operator:\n%s", mintOut)
		}
		// mint also writes the agent paste on the synced folder. That file
		// is copied manually onto agents, so it is a leak path of its own.
		paste, err := ssh(t, 20*time.Second, "pi", "cat /vagrant/vm/policy/generated/agent-credentials-"+slot+".json")
		if err == nil && (contains(paste, "sk-ant") || !contains(paste, phOAT)) {
			t.Fatalf("agent paste file is wrong:\n%s", paste)
		}
	})

	t.Run("enroll list shows both Claude kinds as placeholders only", func(t *testing.T) {
		out := pi(t, "sudo pf enroll list")
		if !lineWith(out, slot, "CLAUDE_OAT", phOAT) || !lineWith(out, slot, "CLAUDE_ORT", phORT) {
			t.Fatalf("slot %s is not listed with both kinds:\n%s", slot, out)
		}
		if contains(out, "sk-ant") {
			t.Fatalf("enroll list printed a live value:\n%s", out)
		}
	})

	// Back up what the claim will overwrite. Then a later group still
	// finds the enrolment that the agent had before this group ran.
	const agentFiles = `"$HOME/.claude/.credentials.json" "$HOME/.pi-fortress/env.sh"`
	_, _ = ssh(t, 20*time.Second, "agent", `for f in `+agentFiles+`; do if [ -f "$f" ]; then cp -p "$f" "$f.pfitest"; else rm -f "$f.pfitest"; fi; done`)
	t.Cleanup(func() {
		_, _ = ssh(t, 20*time.Second, "agent", `for f in `+agentFiles+`; do if [ -f "$f.pfitest" ]; then mv "$f.pfitest" "$f"; else rm -f "$f"; fi; done`)
	})

	t.Run("a claim writes agent credentials holding no sk-ant token", func(t *testing.T) {
		code, command, _ := issueClaim(t, slot, &codes)
		if !contains(command, code) || !contains(command, "/claim/") {
			t.Fatalf("claim command does not carry the code: %q", command)
		}
		if out, err := ssh(t, 3*time.Minute, "agent", command); err != nil {
			t.Fatalf("claim line failed: %v\n%s", err, out)
		}
		// The central promise of the product: the box that runs the agent
		// can read this file, and nothing in it has value to a thief. cat,
		// not grep -c alone: a missing or empty file also greps zero, and
		// that must not count as a pass.
		cred := agent(t, `cat "$HOME/.claude/.credentials.json"`)
		if n := strings.Count(cred, "sk-ant"); n != 0 {
			t.Fatalf("SECRET LEAKED: %d occurrences of sk-ant in the agent's ~/.claude/.credentials.json:\n%s", n, cred)
		}
		if contains(cred, oat) || contains(cred, ort) {
			t.Fatalf("SECRET LEAKED: the minted value reached the agent:\n%s", cred)
		}
		if !contains(cred, phOAT) || !contains(cred, phORT) {
			t.Fatalf("credentials file carries no placeholder, so the zero above proves nothing:\n%s", cred)
		}
		// The documented check that the operator runs, exactly as written.
		// It exits 1 on a zero count, thus the || true.
		out, _ := ssh(t, 20*time.Second, "agent", "grep -c sk-ant $HOME/.claude/.credentials.json || true")
		if strings.TrimSpace(out) != "0" {
			t.Fatalf("grep -c sk-ant said %q, want 0", strings.TrimSpace(out))
		}
		env := agent(t, `cat "$HOME/.pi-fortress/env.sh"`)
		if !contains(env, phOAT) || !contains(env, phORT) || contains(env, "sk-ant") {
			t.Fatalf("env.sh is not placeholders only:\n%s", env)
		}
	})

	t.Run("a claim code is six characters of the unambiguous alphabet", func(t *testing.T) {
		code, _, _ := issueClaim(t, slot, &codes)
		// The faq promises six. The test also asserts the alphabet, because
		// the promise is a code that an operator reads from a screen and
		// types on a different box. An O or a 1 in it causes a support call.
		const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
		if len(code) != 6 {
			t.Fatalf("claim code %q is %d characters, want 6", code, len(code))
		}
		if strings.ContainsFunc(code, func(r rune) bool { return !strings.ContainsRune(alphabet, r) }) {
			t.Fatalf("claim code %q has a character outside %s", code, alphabet)
		}
	})

	t.Run("a claim code expires five minutes after it is issued", func(t *testing.T) {
		_, _, ttl := issueClaim(t, slot, &codes)
		// Measured against the clock of the Pi, read in the same call. The
		// host that runs the suite can be minutes different from the gateway.
		if ttl < 4*time.Minute+30*time.Second || ttl > 5*time.Minute+30*time.Second {
			t.Fatalf("claim code lives %s, want five minutes", ttl)
		}
	})

	t.Run("a claim code is redeemed exactly once", func(t *testing.T) {
		code, _, _ := issueClaim(t, slot, &codes)
		url := "http://" + piIP + "/claim/" + code
		// Fetched without a pipe into a shell: the test is for redemption,
		// not enrolment. The second fetch must find nothing.
		get := func() string {
			out, _ := ssh(t, 30*time.Second, "agent", "curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "+url)
			return strings.TrimSpace(out)
		}
		if first := get(); first != "200" {
			t.Fatalf("first redemption of a fresh code got %s, want 200", first)
		}
		if second := get(); second != "404" {
			t.Fatalf("second redemption of the same code got %s, want 404: a claim code is reusable", second)
		}
	})

	// The revoke pair, last because it removes the slot. The first half
	// gives the second half its meaning. Without it, a 503 could come from
	// a lab that never did a substitution.
	core := func(auth string) (string, string) {
		t.Helper()
		body, _ := ssh(t, 20*time.Second, "agent", "curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 4 --max-time 10 -H 'Authorization: Bearer "+auth+"' https://pf-core-echo.test/")
		out, _ := ssh(t, 20*time.Second, "agent", "curl -sS --connect-timeout 4 --max-time 10 -H 'Authorization: Bearer "+auth+"' https://pf-core-echo.test/")
		return strings.TrimSpace(body), out
	}
	t.Run("the minted placeholder is substituted while the slot exists", func(t *testing.T) {
		if !hasCoreEcho(t) {
			t.Skip("no pf-core-echo.test on this gateway: installCoreEcho could not lend it one")
		}
		eventually(t, 30*time.Second, func() string {
			code, body := core(phOAT)
			if code == "200" && contains(body, `"substituted": true`) && contains(body, oat) {
				return ""
			}
			return "core echo did not substitute the minted slot: " + code + "\n" + body
		})
	})

	t.Run("deleting the slot turns the next request into a 503", func(t *testing.T) {
		out := pi(t, "sudo pf enroll delete --slot "+slot)
		if !contains(out, "deleted slot="+slot) {
			t.Fatalf("delete did not report the slot:\n%s", out)
		}
		if !hasCoreEcho(t) {
			t.Skip("slot deleted; no pf-core-echo.test on this gateway to read the 503 from")
		}
		eventually(t, 30*time.Second, func() string {
			code, body := core(phOAT)
			if code != "503" {
				return "revoked placeholder still gets " + code + "\n" + body
			}
			// The refusal names no cause and carries no value: a body that
			// still holds the token would be a leak on the way out.
			if !contains(body, "this request could not be completed") || contains(body, oat) {
				return "refusal body is wrong:\n" + body
			}
			return ""
		})
	})
}

// issueClaim mints a one-time code for slot as Secrets 'c' in the TUI
// does, without a terminal (internal/cli/claim.go). It reports the code
// lifetime that the gateway gives, measured against the clock of the
// gateway, read in the same round trip. Each code is recorded, so that the
// group can remove the claim file that it left in the www directory.
func issueClaim(t *testing.T, slot string, codes *[]string) (code, command string, ttl time.Duration) {
	t.Helper()
	out := pi(t, "date -u +%s; sudo pf claim -slot "+slot)
	now, err := strconv.ParseInt(strings.TrimSpace(firstLine(out)), 10, 64)
	if err != nil {
		t.Fatalf("no clock from the Pi:\n%s", out)
	}
	code = field(out, "code")
	command = field(out, "command")
	if code == "" || command == "" {
		t.Fatalf("pf claim printed no code:\n%s", out)
	}
	*codes = append(*codes, code)
	exp, err := time.Parse(time.RFC3339, field(out, "expires"))
	if err != nil {
		t.Fatalf("unparseable expiry:\n%s", out)
	}
	return code, command, time.Duration(exp.Unix()-now) * time.Second
}

// field returns the value of the first key=value line in the output of a
// pf command. The value is all of the remaining line, with its spaces. The
// command= line of a claim is a full shell line.
func field(out, key string) string {
	for line := range strings.SplitSeq(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key+"="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstLine(out string) string {
	line, _, _ := strings.Cut(out, "\n")
	return line
}
