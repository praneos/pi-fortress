package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/admin"
	"pi-fortress/internal/audit"
	"pi-fortress/internal/feedstage"
)

// feedsBox is a policy directory, the input and state directories of the
// download, and a fake unit.
type feedsBox struct {
	t       *testing.T
	policy  string
	gen     string
	in      string
	state   string
	log     string
	started int
	// stage runs as the fake unit. It gets the request that root wrote.
	stage func(b *feedsBox, req feedstage.Request) error
}

func newFeedsBox(t *testing.T) *feedsBox {
	t.Helper()
	dir := t.TempDir()
	b := &feedsBox{
		t:      t,
		policy: filepath.Join(dir, "policy"),
		in:     filepath.Join(dir, "feeds-in"),
		state:  filepath.Join(dir, "state"),
		log:    filepath.Join(dir, "audit.jsonl"),
	}
	b.gen = filepath.Join(b.policy, "generated")
	for _, d := range []string{b.gen, filepath.Join(b.state, feedstage.StageName)} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	b.write(filepath.Join(b.policy, "sources.json"), `{"feeds":[{"id":"ips"},{"id":"doms"}]}`)
	b.write(filepath.Join(b.policy, "never_block.ips"), "192.0.2.200\n")
	b.write(filepath.Join(b.gen, "blacklist.ips"), "192.0.2.9\n")
	b.write(filepath.Join(b.gen, "blacklist.domains"), "old.example.com\n")
	t.Setenv(audit.PathEnv, b.log)
	was := newFeedsHost
	newFeedsHost = func() feedsHost {
		return feedsHost{
			geteuid:  func() int { return 0 },
			inputDir: b.in,
			stateDir: b.state,
			lock:     func() (func(), error) { return func() {}, nil },
			start: func() ([]byte, error) {
				b.started++
				raw, err := os.ReadFile(filepath.Join(b.in, feedstage.RequestFile))
				if err != nil {
					return nil, err
				}
				req, err := feedstage.ParseRequest(raw)
				if err != nil {
					return nil, err
				}
				if b.stage == nil {
					return nil, nil
				}
				if err := b.stage(b, req); err != nil {
					return []byte("Job failed.\x1b[0m\n"), err
				}
				return nil, nil
			},
			uid: func() (int, error) { return os.Getuid(), nil },
		}
	}
	t.Cleanup(func() { newFeedsHost = was })
	return b
}

func (b *feedsBox) write(path, text string) {
	b.t.Helper()
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		b.t.Fatal(err)
	}
}

func (b *feedsBox) put(name, text string) {
	b.write(filepath.Join(b.state, feedstage.StageName, name), text)
}

func (b *feedsBox) read(path string) string {
	b.t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		b.t.Fatal(err)
	}
	return string(raw)
}

func (b *feedsBox) run(args ...string) (int, string, string) {
	var stdout, stderr strings.Builder
	code := runFeeds(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// goodStage writes a set that passes the check, with the run id of req.
func goodStage(b *feedsBox, req feedstage.Request) error {
	b.put("blacklist.ips", "192.0.2.1\n")
	b.put("blacklist.domains", "pi-fortress-block.test\n")
	b.put("feeds.map", "192.0.2.1\tips\n")
	b.put("fetch.report", "OK ips: 1 ips\nOK doms: 1 domains\n")
	b.put("run", req.Run+"\n")
	return nil
}

func TestFeedsRunImportsTheStageOfThisRun(t *testing.T) {
	b := newFeedsBox(t)
	if err := os.MkdirAll(filepath.Join(b.gen, "feeds"), 0755); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	b.write(filepath.Join(b.gen, "feeds", "ips.list"), "# feed x\n192.0.2.1\n")
	if err := os.Chtimes(filepath.Join(b.gen, "feeds", "ips.list"), old, old); err != nil {
		t.Fatal(err)
	}
	var got feedstage.Request
	b.stage = func(b *feedsBox, req feedstage.Request) error {
		got = req
		return goodStage(b, req)
	}
	code, stdout, stderr := b.run("run", "-policy", b.policy, "-fresh", "30m")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if got.Fresh != 30*time.Minute || b.started != 1 {
		t.Fatalf("request %+v, starts %d", got, b.started)
	}
	if s := b.read(filepath.Join(b.gen, "blacklist.ips")); s != "192.0.2.1\n" {
		t.Fatalf("blacklist.ips = %q", s)
	}
	if s := b.read(filepath.Join(b.gen, "sample.domain")); s != "pi-fortress-block.test\n" {
		t.Fatalf("sample.domain = %q", s)
	}
	if !strings.Contains(stdout, "OK ips: 1 ips") || !strings.Contains(stdout, "imported 1 ips, 1 domains") {
		t.Fatalf("stdout:\n%s", stdout)
	}
	// The inputs: copies of the policy files that exist, and the seed.
	if s := b.read(filepath.Join(b.in, "sources.json")); !strings.Contains(s, `"ips"`) {
		t.Fatalf("sources.json copy %q", s)
	}
	if s := b.read(filepath.Join(b.in, "never_block.ips")); s != "192.0.2.200\n" {
		t.Fatalf("never_block.ips copy %q", s)
	}
	if _, err := os.Stat(filepath.Join(b.in, "never_block.domains")); !os.IsNotExist(err) {
		t.Fatalf("a missing policy file got a copy: %v", err)
	}
	fi, err := os.Stat(filepath.Join(b.in, "seed", "ips.list"))
	if err != nil || !fi.ModTime().Equal(old) {
		t.Fatalf("seed copy: %v %v", fi, err)
	}
	raw := b.read(b.log)
	if !strings.Contains(raw, `"verb":"fetch"`) || !strings.Contains(raw, `"ips":"1"`) {
		t.Fatalf("audit entry: %s", raw)
	}
}

func TestFeedsRunKeepsTheListsWhenTheUnitFails(t *testing.T) {
	b := newFeedsBox(t)
	// A set of an earlier run is still in the stage.
	b.put("blacklist.ips", "192.0.2.1\n")
	b.put("run", strings.Repeat("0", 32)+"\n")
	b.stage = func(*feedsBox, feedstage.Request) error { return errors.New("exit status 1") }
	code, stdout, stderr := b.run("run", "-policy", b.policy)
	if code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if s := b.read(filepath.Join(b.gen, "blacklist.ips")); s != "192.0.2.9\n" {
		t.Fatalf("blacklist.ips changed to %q", s)
	}
	if s := b.read(filepath.Join(b.gen, "fetch.report")); !strings.HasPrefix(s, "FAIL download: pi-fortress-feeds.service wrote no set") {
		t.Fatalf("report %q", s)
	}
	if strings.Contains(stderr, "\x1b") {
		t.Fatalf("stderr has a control byte: %q", stderr)
	}
	if raw := b.read(b.log); !strings.Contains(raw, `"ok":false`) || !strings.Contains(raw, `"unit":"failed"`) {
		t.Fatalf("audit entry: %s", raw)
	}
}

func TestFeedsRunKeepsTheListsWhenAllFeedsFail(t *testing.T) {
	b := newFeedsBox(t)
	b.stage = func(b *feedsBox, req feedstage.Request) error {
		b.put("fetch.report", "FAIL ips: HTTP 503\n")
		b.put("run", req.Run+"\n")
		return errors.New("exit status 1")
	}
	code, stdout, _ := b.run("run", "-policy", b.policy)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if s := b.read(filepath.Join(b.gen, "blacklist.ips")); s != "192.0.2.9\n" {
		t.Fatalf("blacklist.ips changed to %q", s)
	}
	if s := b.read(filepath.Join(b.gen, "fetch.report")); s != "FAIL ips: HTTP 503\n" {
		t.Fatalf("report %q", s)
	}
	if !strings.Contains(stdout, "imported unchanged ips, unchanged domains") {
		t.Fatalf("stdout:\n%s", stdout)
	}
}

func TestFeedsRunRefusesABadStage(t *testing.T) {
	b := newFeedsBox(t)
	b.stage = func(b *feedsBox, req feedstage.Request) error {
		if err := goodStage(b, req); err != nil {
			return err
		}
		b.put("blacklist.ips", "192.0.2.1\n1.2.3.4 } ; flush ruleset\n")
		return nil
	}
	code, stdout, stderr := b.run("run", "-policy", b.policy)
	if code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, name := range []string{"blacklist.ips", "blacklist.domains"} {
		if s := b.read(filepath.Join(b.gen, name)); s != map[string]string{"blacklist.ips": "192.0.2.9\n", "blacklist.domains": "old.example.com\n"}[name] {
			t.Fatalf("%s changed to %q", name, s)
		}
	}
	report := b.read(filepath.Join(b.gen, "fetch.report"))
	if !strings.HasPrefix(report, "FAIL stage: blacklist.ips: line 2") || strings.Contains(report, "flush") {
		t.Fatalf("report %q", report)
	}
	if raw := b.read(b.log); !strings.Contains(raw, `"refused":"blacklist.ips: line 2`) {
		t.Fatalf("audit entry: %s", raw)
	}
}

// An error that is not a refusal and not a missing set (here: the stage
// is a file) also replaces the report of the earlier run with a FAIL line,
// and leaves the lists.
func TestFeedsRunWritesFailImportForAnyOtherError(t *testing.T) {
	b := newFeedsBox(t)
	b.write(filepath.Join(b.gen, "fetch.report"), "OK ips: 1 ips\n")
	stage := filepath.Join(b.state, feedstage.StageName)
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	b.write(stage, "not a directory\x1b[2J\n")
	code, stdout, stderr := b.run("run", "-policy", b.policy)
	if code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	want := "FAIL import: the import of the stage stopped on an error; pf feeds run prints the error\n"
	if s := b.read(filepath.Join(b.gen, "fetch.report")); s != want {
		t.Fatalf("report %q", s)
	}
	if s := b.read(filepath.Join(b.gen, "blacklist.ips")); s != "192.0.2.9\n" {
		t.Fatalf("blacklist.ips changed to %q", s)
	}
	if !strings.Contains(stderr, "is not a directory") || strings.ContainsAny(stdout+stderr, "\x1b") {
		t.Fatalf("stderr %q", stderr)
	}
	if raw := b.read(b.log); !strings.Contains(raw, `"stage":"error"`) || !strings.Contains(raw, `"ok":false`) {
		t.Fatalf("audit entry: %s", raw)
	}
}

func TestFeedsImportTakesTheRunIDOfTheStage(t *testing.T) {
	b := newFeedsBox(t)
	run := strings.Repeat("5a", 16)
	if err := goodStage(b, feedstage.Request{Run: run}); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := b.run("import", "-run", run, "-policy", b.policy); code != 0 || b.started != 0 {
		t.Fatalf("exit %d, starts %d\n%s\n%s", code, b.started, out, errs)
	}
	if s := b.read(filepath.Join(b.gen, "blacklist.ips")); s != "192.0.2.1\n" {
		t.Fatalf("blacklist.ips = %q", s)
	}
	for _, args := range [][]string{
		{"import", "-policy", b.policy},
		{"import", "-run", "xyz", "-policy", b.policy},
		{"run", "-run", run, "-policy", b.policy},
		{"run", "-fresh", "25h", "-policy", b.policy},
		{"bogus"},
		{},
	} {
		if code, _, _ := b.run(args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
}

func TestFeedsNeedsRootAndTheLock(t *testing.T) {
	b := newFeedsBox(t)
	host := newFeedsHost
	newFeedsHost = func() feedsHost {
		h := host()
		h.geteuid = func() int { return 1000 }
		return h
	}
	if code, _, errs := b.run("run", "-policy", b.policy); code != 2 || !strings.Contains(errs, "root only") {
		t.Fatalf("not root: exit %d %s", code, errs)
	}
	newFeedsHost = func() feedsHost {
		h := host()
		h.lock = func() (func(), error) { return nil, admin.ErrLocked }
		return h
	}
	if code, _, _ := b.run("run", "-policy", b.policy); code != 75 || b.started != 0 {
		t.Fatalf("lock held: exit %d, starts %d", code, b.started)
	}
}

// pf apply and the TUI hold the lock and start pf feeds with the
// descriptor open. pf feeds then uses that descriptor and does not wait
// for a lock that its own parent holds.
func TestInheritedLockSeesTheOpenLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apply.lock")
	if inheritedLock(path) {
		t.Fatal("no lock file, but inheritedLock is true")
	}
	l, err := admin.TryLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if !inheritedLock(path) {
		t.Fatal("this process holds the lock, but inheritedLock is false")
	}
	release, err := applyLockOrInherited(path)
	if err != nil {
		t.Fatalf("the inherited lock was refused: %v", err)
	}
	release()
	l.Release()
	if inheritedLock(path) {
		t.Fatal("the lock is released, but inheritedLock is true")
	}
	release, err = applyLockOrInherited(path)
	if err != nil {
		t.Fatalf("a free lock was refused: %v", err)
	}
	release()
}

func TestFeedInputsRemoveAFileThatIsGone(t *testing.T) {
	b := newFeedsBox(t)
	b.write(filepath.Join(b.policy, "never_block.domains"), "keep.example.com\n")
	req := feedstage.Request{Run: strings.Repeat("1", 32)}
	if err := writeFeedInputs(b.in, b.policy, req); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(b.policy, "never_block.domains")); err != nil {
		t.Fatal(err)
	}
	if err := writeFeedInputs(b.in, b.policy, req); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.in, "never_block.domains")); !os.IsNotExist(err) {
		t.Fatalf("the copy of a removed file stays: %v", err)
	}
	fi, err := os.Stat(filepath.Join(b.in, "request"))
	if err != nil || fi.Mode().Perm() != 0644 {
		t.Fatalf("request: %v %v", fi, err)
	}
	if err := os.Remove(filepath.Join(b.in, "request")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b.state, filepath.Join(b.in, "link")); err != nil {
		t.Fatal(err)
	}
	if err := writeFeedInputs(filepath.Join(b.in, "link"), b.policy, req); err == nil {
		t.Fatal("inputs went through a link")
	}
}
