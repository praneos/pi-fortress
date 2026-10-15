package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/testsupport"
)

// box builds a plausible deployed Pi: the config and policy of the operator,
// and beside them the credentials and identity that must never leave it.
func box(t *testing.T) (Config, string, string) {
	t.Helper()
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	pol := filepath.Join(root, "policy")
	write := func(p, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(etc, "net.env"), "INT_IF=eth0\nWAN_IF=wlan0\n", 0644)
	write(filepath.Join(etc, "net.env.local"), "FEED_REFRESH=1\n", 0644)
	write(filepath.Join(etc, "house.env"), "HOUSE_IF=eth1\n", 0644)
	write(filepath.Join(etc, "segments.d", "lab.env"), "SEG_NAME=lab\n", 0644)
	write(filepath.Join(etc, "segments.d", "notes.txt"), "ignored\n", 0644)
	// The three things a backup must never carry.
	write(filepath.Join(etc, "broker", "secrets.env"), "0123456789abcdef_TOKEN=sk-live-supersecret\n", 0600)
	write(filepath.Join(etc, "mullvad.conf"), "PrivateKey = wgsecretkeyhere=\n", 0600)
	write(filepath.Join(etc, "engine", "ca.pem"), "-----BEGIN PRIVATE KEY-----\ncakeymaterial\n", 0600)
	// Compiled output, which apply rewrites.
	write(filepath.Join(etc, "blocked-domains.conf"), "address=/evil.test/0.0.0.0\n", 0644)
	write(filepath.Join(etc, "paranoid.flags"), "0\n", 0644)

	write(filepath.Join(pol, "blacklist.domains"), "evil.test\n", 0644)
	write(filepath.Join(pol, "never_block.domains"), "bank.example\n", 0644)
	write(filepath.Join(pol, "allow.domains"), "api.example\n", 0644)
	write(filepath.Join(pol, "sources.json"), `{"feeds":[]}`, 0644)
	write(filepath.Join(pol, "alert.url"), "https://hooks.example/x\n", 0600)
	write(filepath.Join(pol, "generated", "blacklist.domains"), "fromfeed.test\n", 0644)
	write(filepath.Join(pol, "generated", "egress-ca.pem"), "-----BEGIN CERTIFICATE-----\n", 0644)

	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	return Config{EtcDir: etc, PolicyDir: pol, Host: "pi-fortress", Now: func() time.Time { return now }}, etc, pol
}

func archive(t *testing.T, c Config) (*bytes.Buffer, Manifest) {
	t.Helper()
	var buf bytes.Buffer
	man, err := c.Write(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return &buf, man
}

// The full format depends on this guarantee: a stolen backup is not a
// credential dump, and a restore cannot overwrite an identity because it
// never had one. This test reads the raw bytes, not the file list, so a
// secret smuggled into some other file also fails.
func TestArchiveNeverCarriesSecretsOrIdentity(t *testing.T) {
	c, _, _ := box(t)
	buf, man := archive(t, c)
	raw := buf.Bytes()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	flat, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"sk-live-supersecret", "wgsecretkeyhere", "cakeymaterial", "BEGIN PRIVATE KEY"} {
		if bytes.Contains(flat, []byte(needle)) {
			t.Fatalf("archive carries %q", needle)
		}
	}
	for _, f := range man.Files {
		for _, bad := range []string{"secrets", "mullvad", "ca.pem", "wireguard"} {
			if strings.Contains(strings.ToLower(f.Name), bad) {
				t.Fatalf("archive lists %q", f.Name)
			}
		}
	}
	// And it says so in the archive, where an operator who rebuilds in two
	// years will actually look.
	if len(man.Excluded) == 0 {
		t.Fatal("manifest does not say what it left out")
	}
	var joined string
	for _, e := range man.Excluded {
		joined += e.What + e.Redo
	}
	for _, want := range []string{"secrets.env", "ca.pem", "pf enroll", "init-ca"} {
		if !strings.Contains(joined, want) {
			t.Errorf("exclusions do not mention %q", want)
		}
	}
}

// apply rebuilds compiled output. So a copy in the archive would restore a
// stale copy of something that apply is about to overwrite.
func TestArchiveSkipsCompiledAndGenerated(t *testing.T) {
	c, _, _ := box(t)
	_, man := archive(t, c)
	for _, f := range man.Files {
		if strings.Contains(f.Name, "generated/") || strings.HasSuffix(f.Name, ".conf") || strings.HasSuffix(f.Name, ".flags") {
			t.Errorf("archive carries compiled output %q", f.Name)
		}
	}
}

func TestArchiveCarriesOperatorState(t *testing.T) {
	c, _, _ := box(t)
	_, man := archive(t, c)
	got := map[string]bool{}
	for _, f := range man.Files {
		got[f.Name] = true
	}
	for _, want := range []string{
		"etc/net.env", "etc/net.env.local", "etc/house.env", "etc/segments.d/lab.env",
		"policy/blacklist.domains", "policy/never_block.domains", "policy/allow.domains",
		"policy/sources.json", "policy/alert.url",
	} {
		if !got[want] {
			t.Errorf("archive is missing %q", want)
		}
	}
	if got["etc/segments.d/notes.txt"] {
		t.Error("archive carries a non-.env file from segments.d")
	}
}

// An ordinary tar must work: at the time a backup is necessary, the tool
// that wrote it may be the thing that died.
func TestArchiveIsAnOrdinaryTarWithTheManifestFirst(t *testing.T) {
	c, _, _ := box(t)
	buf, _ := archive(t, c)
	gz, err := gzip.NewReader(buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != ManifestName {
		t.Fatalf("first entry is %q, want the manifest", h.Name)
	}
	var man Manifest
	if err := json.NewDecoder(tr).Decode(&man); err != nil {
		t.Fatal(err)
	}
	if man.Schema != Schema || man.Host != "pi-fortress" {
		t.Fatalf("%+v", man)
	}
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("entries are not in a stable order: %v", names)
	}
}

func TestRoundTripRestoresOntoAnEmptyBox(t *testing.T) {
	c, _, srcPol := box(t)
	buf, _ := archive(t, c)
	arc, err := Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	dstEtc, dstPol := filepath.Join(dst, "etc"), filepath.Join(dst, "policy")
	plan, err := arc.Plan(dstEtc, dstPol)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range plan.Changes {
		if ch.Kind != "new" {
			t.Fatalf("%s on an empty box is %q", ch.Name, ch.Kind)
		}
	}
	// The plan is a plan: nothing is on disk until Apply.
	if _, err := os.Stat(filepath.Join(dstPol, "blacklist.domains")); err == nil {
		t.Fatal("Plan wrote a file")
	}
	done, err := plan.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != len(plan.Changes) {
		t.Fatalf("wrote %d of %d", len(done), len(plan.Changes))
	}
	if got := testsupport.ReadFile(t, filepath.Join(dstPol, "blacklist.domains")); got != "evil.test\n" {
		t.Fatalf("restored %q", got)
	}
	if got := testsupport.ReadFile(t, filepath.Join(dstEtc, "segments.d", "lab.env")); got != "SEG_NAME=lab\n" {
		t.Fatalf("restored %q", got)
	}
	// alert.url is a webhook URL, and it came from disk at 0600.
	st, err := os.Stat(filepath.Join(dstPol, "alert.url"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("alert.url restored as %v, want the 0600 it was backed up at", st.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(srcPol, "generated")); err != nil {
		t.Fatal("the source box was modified")
	}
}

// A restore that quietly rewrites files that an operator edited after the
// backup is the downgrade that this feature could most easily become. The
// diff is the defence, so it must be accurate.
func TestPlanNamesWhatWouldChange(t *testing.T) {
	c, _, _ := box(t)
	buf, _ := archive(t, c)
	arc, err := Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	dstEtc, dstPol := filepath.Join(dst, "etc"), filepath.Join(dst, "policy")
	if err := os.MkdirAll(dstPol, 0755); err != nil {
		t.Fatal(err)
	}
	// One identical, one edited since.
	if err := os.WriteFile(filepath.Join(dstPol, "blacklist.domains"), []byte("evil.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dstPol, "never_block.domains"), []byte("bank.example\nhospital.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	plan, err := arc.Plan(dstEtc, dstPol)
	if err != nil {
		t.Fatal(err)
	}
	kind := map[string]string{}
	for _, ch := range plan.Changes {
		kind[ch.Name] = ch.Kind
	}
	if kind["policy/blacklist.domains"] != "same" {
		t.Errorf("identical file reported %q", kind["policy/blacklist.domains"])
	}
	if kind["policy/never_block.domains"] != "changed" {
		t.Errorf("an edited never_block reported %q; this is the entry a restore would silently drop", kind["policy/never_block.domains"])
	}
	if kind["etc/house.env"] != "new" {
		t.Errorf("absent file reported %q", kind["etc/house.env"])
	}
	for _, ch := range plan.Changed() {
		if ch.Kind == "same" {
			t.Error("Changed() returned an unchanged file")
		}
	}
	if len(plan.Changed()) != len(plan.Changes)-1 {
		t.Fatalf("%d changed of %d", len(plan.Changed()), len(plan.Changes))
	}
}

// A restore of a backup from different hardware is a real use: it is most
// of the reason for a backup. But a restore by accident must be loud.
// apply refuses a profile pinned to an interface that is not there, and
// that failure looks like a broken box, not like the wrong backup.
func TestPlanWarnsWhenTheHardwareDiffers(t *testing.T) {
	c, _, _ := box(t)
	buf, _ := archive(t, c)
	arc, err := Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	dstEtc := filepath.Join(dst, "etc")
	if err := os.MkdirAll(dstEtc, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dstEtc, "net.env"), []byte("INT_IF=enp6s0.20\nWAN_IF=wlan0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	plan, err := arc.Plan(dstEtc, filepath.Join(dst, "policy"))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan.Warnings, "\n")
	if !strings.Contains(joined, "INT_IF") || !strings.Contains(joined, "enp6s0.20") {
		t.Fatalf("no warning about the changed interface: %v", plan.Warnings)
	}
	if strings.Contains(joined, "WAN_IF") {
		t.Fatalf("warned about an interface that matches: %v", plan.Warnings)
	}
}

// The archive is attacker-supplied from the moment it comes from a laptop.
func TestReadRefusesAPathOutsideTheSet(t *testing.T) {
	bad := []string{
		"../../etc/shadow",
		"/etc/pi-fortress/broker/secrets.env",
		"etc/../../root/.ssh/authorized_keys",
		"etc/broker/secrets.env",
		"policy/generated/egress-ca.pem",
		"etc/mullvad.conf",
		"etc/segments.d/../../x.env",
		"etc/segments.d/deep/x.env",
		"policy/../etc/net.env",
	}
	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			if safeName(name) {
				t.Fatalf("safeName accepted %q", name)
			}
			_, err := Read(tarOf(t, map[string]string{ManifestName: `{"schema":1}`, name: "x"}))
			if err == nil {
				t.Fatalf("Read accepted %q", name)
			}
		})
	}
	for _, good := range []string{"etc/net.env", "etc/segments.d/lab.env", "policy/sources.json", "policy/alert.url", ManifestName} {
		if !safeName(good) {
			t.Errorf("safeName rejected %q", good)
		}
	}
}

func TestReadRefusesATamperedArchive(t *testing.T) {
	c, _, _ := box(t)
	buf, man := archive(t, c)
	arc, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the archive with the contents of one file swapped, and with the
	// manifest unchanged.
	files := map[string]string{}
	mj, err := json.Marshal(man)
	if err != nil {
		t.Fatal(err)
	}
	files[ManifestName] = string(mj)
	for n, b := range arc.Body {
		files[n] = string(b)
	}
	files["policy/never_block.domains"] = "nothing.example\n"
	if _, err := Read(tarOf(t, files)); err == nil {
		t.Fatal("a file edited after the backup was written restored anyway")
	}
}

func TestReadRefusesANewerSchema(t *testing.T) {
	_, err := Read(tarOf(t, map[string]string{ManifestName: `{"schema":99}`}))
	if err == nil || !strings.Contains(err.Error(), "newer pf") {
		t.Fatalf("err %v", err)
	}
}

func TestReadRefusesAnArchiveWithNoManifest(t *testing.T) {
	if _, err := Read(tarOf(t, map[string]string{"etc/net.env": "x"})); err != ErrNoMan {
		t.Fatalf("err %v", err)
	}
}

func tarOf(t *testing.T, files map[string]string) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == ManifestName {
			return true
		}
		if names[j] == ManifestName {
			return false
		}
		return names[i] < names[j]
	})
	for _, n := range names {
		body := []byte(files[n])
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0644, Size: int64(len(body)), Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

// PI_OWNED in the Makefile drives the rsync --delete exclusions for make
// pi-ship. If a TUI-editable list is not in it, the next ship deletes that
// list from the Pi, and the operator learns this when the list is empty.
// The two copies agree today. This test keeps them in agreement.
func TestPiOwnedMatchesMakefile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testsupport.RepoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^PI_OWNED = (.*)$`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("Makefile no longer defines PI_OWNED; this test and internal/backup both depend on it")
	}
	got := strings.Fields(string(m[1]))
	sort.Strings(got)
	want := PiOwned()
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("Makefile PI_OWNED and backup.PiOwned() disagree.\n  Makefile: %v\n  Go:       %v\nA file only in the Go list is deleted from the Pi by make pi-ship; a file only in the Makefile is never backed up.", got, want)
	}
	// alert.url is Pi-owned, but it is excluded by name, not through PI_OWNED.
	// So PolicyFiles carries one more file than PiOwned does.
	if !bytes.Contains(raw, []byte("--exclude '/vm/policy/alert.url'")) {
		t.Error("the Makefile no longer excludes alert.url from --delete")
	}
	if len(PolicyFiles()) != len(want)+1 {
		t.Errorf("PolicyFiles has %d entries, PiOwned %d", len(PolicyFiles()), len(want))
	}
}

func TestEnvValuesIgnoresWhatItCannotReadPlainly(t *testing.T) {
	got := envValues([]string{"A", "B", "C", "D"}, "A=1\n# B=2\nexport C=\"3\"\nD=$(hostname)\nE=5\n")
	want := map[string]string{"A": "1", "C": "3"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}
