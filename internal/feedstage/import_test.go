package feedstage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"pi-fortress/internal/eyeball"
)

// stage is a state directory with a stage in it, and a generated/ to
// import into.
type stage struct {
	t     *testing.T
	state string
	dir   string
	out   string
	run   string
}

func newStage(t *testing.T) *stage {
	t.Helper()
	s := &stage{t: t, state: t.TempDir(), out: t.TempDir()}
	s.dir = filepath.Join(s.state, StageName)
	if err := os.Mkdir(s.dir, 0700); err != nil {
		t.Fatal(err)
	}
	run, err := NewRun()
	if err != nil {
		t.Fatal(err)
	}
	s.run = run
	s.put(RunFile, run+"\n")
	return s
}

func (s *stage) put(name, text string) {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, name), []byte(text), 0600); err != nil {
		s.t.Fatal(err)
	}
}

func (s *stage) cfg() Config {
	return Config{
		StateDir: s.state,
		OutDir:   s.out,
		Limits:   Limits{MaxIPs: 100, MaxDomains: 100, FeedIDs: map[string]bool{"hagezi": true, "feodo": true}},
		Run:      s.run,
		UID:      os.Getuid(),
	}
}

func (s *stage) read(name string) string {
	s.t.Helper()
	b, err := os.ReadFile(filepath.Join(s.out, name))
	if err != nil {
		s.t.Fatal(err)
	}
	return string(b)
}

func eyeballText(t *testing.T) string {
	t.Helper()
	rg, ok := eyeball.ParseRange("1.0.0.0", "1.0.0.255", "64500")
	if !ok {
		t.Fatal("ParseRange")
	}
	var b bytes.Buffer
	if err := eyeball.Write(&b, time.Date(2026, 10, 1, 4, 0, 0, 0, time.UTC), []eyeball.Range{rg}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// good stages a full set that passes the check.
func (s *stage) good() {
	s.put(IPsFile, "192.0.2.1\n1.2.3.0/24\n")
	s.put(DomainsFile, "192.0.2.7\npi-fortress-block.test\nads.example.com\n")
	s.put(HouseDomainsFile, "tracker.example.net\n")
	s.put(HouseVPNFile, "")
	s.put(FeedsMapFile, "192.0.2.1\tfeodo\npi-fortress-block.test\thagezi\n")
	// A comment and an empty line: Parse takes them, and the import
	// writes the table in the form of Write.
	s.put(EyeballFile, strings.Replace(eyeballText(s.t), "\n1.0.0.0", "\n# note\n\n1.0.0.0", 1))
	s.put(ReportFile, "OK hagezi: 2 domains\nFAIL x: \x1b[31mred\n")
}

func TestImportWritesTheCheckedSet(t *testing.T) {
	s := newStage(t)
	s.good()
	res, err := Import(s.cfg())
	if err != nil || !res.Imported || res.Refused != "" {
		t.Fatalf("Import: %+v %v", res, err)
	}
	if res.IPs != 2 || res.Domains != 3 {
		t.Fatalf("counts: %+v", res)
	}
	for name, want := range map[string]string{
		IPsFile:          "192.0.2.1\n1.2.3.0/24\n",
		DomainsFile:      "192.0.2.7\npi-fortress-block.test\nads.example.com\n",
		HouseDomainsFile: "tracker.example.net\n",
		HouseVPNFile:     "",
		FeedsMapFile:     "192.0.2.1\tfeodo\npi-fortress-block.test\thagezi\n",
		EyeballFile:      eyeballText(t),
		SampleFile:       "pi-fortress-block.test\n",
		ReportFile:       "OK hagezi: 2 domains\nFAIL x: ?[31mred\n",
	} {
		if got := s.read(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	fi, err := os.Stat(filepath.Join(s.out, IPsFile))
	if err != nil || fi.Mode().Perm() != 0644 {
		t.Fatalf("mode of an imported list: %v %v", fi.Mode(), err)
	}
}

// old puts a previous set into generated/ and gives a copy of it.
func (s *stage) old() map[string]string {
	s.t.Helper()
	prev := map[string]string{
		IPsFile:     "192.0.2.9\n",
		DomainsFile: "old.example.com\n",
		SampleFile:  "old.example.com\n",
		ReportFile:  "OK old: 1 ips\n",
	}
	for name, text := range prev {
		if err := os.WriteFile(filepath.Join(s.out, name), []byte(text), 0644); err != nil {
			s.t.Fatal(err)
		}
	}
	return prev
}

func (s *stage) unchanged(prev map[string]string) {
	s.t.Helper()
	ents, err := os.ReadDir(s.out)
	if err != nil {
		s.t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() == ReportFile {
			continue
		}
		want, ok := prev[e.Name()]
		if !ok {
			s.t.Errorf("generated/ got a new file %s", e.Name())
			continue
		}
		if got := s.read(e.Name()); got != want {
			s.t.Errorf("generated/%s changed to %q", e.Name(), got)
		}
	}
}

func TestImportRefusesTheWholeSetForOneBadFile(t *testing.T) {
	for name, c := range map[string]struct {
		setup func(s *stage)
		want  string
	}{
		"bad line in the house list": {func(s *stage) { s.put(HouseDomainsFile, "tracker.example.net\nx.com }\n") }, "house.domains: line 2: byte 0x20"},
		"rule text in the ip list":   {func(s *stage) { s.put(IPsFile, "192.0.2.1\n1.2.3.4;flush ruleset\n") }, "blacklist.ips: line 2"},
		"address in the vpn list":    {func(s *stage) { s.put(HouseVPNFile, "192.0.2.1\n") }, "house_vpn.domains: line 1"},
		"map item not in a list":     {func(s *stage) { s.put(FeedsMapFile, "other.example.com\thagezi\n") }, "feeds.map: line 1"},
		"map feed not in sources":    {func(s *stage) { s.put(FeedsMapFile, "192.0.2.1\tother\n") }, "feeds.map: line 1"},
		"eyeball table not a table":  {func(s *stage) { s.put(EyeballFile, "1.0.0.0 1.0.0.255 64500\n") }, "eyeball.table"},
		"list over the count cap":    {func(s *stage) { s.put(IPsFile, "1.2.3.1\n1.2.3.2\n1.2.3.3\n") }, "more than the cap of 2"},
		"link out of the stage": {func(s *stage) {
			outside := filepath.Join(s.t.TempDir(), "secret.domains")
			if err := os.WriteFile(outside, []byte("secret.example.com\n"), 0600); err != nil {
				s.t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(s.dir, DomainsFile)); err != nil {
				s.t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(s.dir, DomainsFile)); err != nil {
				s.t.Fatal(err)
			}
		}, "blacklist.domains: not a regular file"},
		"link inside the stage": {func(s *stage) {
			if err := os.Remove(filepath.Join(s.dir, HouseVPNFile)); err != nil {
				s.t.Fatal(err)
			}
			if err := os.Symlink(HouseDomainsFile, filepath.Join(s.dir, HouseVPNFile)); err != nil {
				s.t.Fatal(err)
			}
		}, "house_vpn.domains: not a regular file"},
		"fifo in place of a list": {func(s *stage) {
			if err := os.Remove(filepath.Join(s.dir, IPsFile)); err != nil {
				s.t.Fatal(err)
			}
			if err := syscall.Mkfifo(filepath.Join(s.dir, IPsFile), 0600); err != nil {
				s.t.Fatal(err)
			}
		}, "blacklist.ips: not a regular file"},
		"directory in place of a list": {func(s *stage) {
			if err := os.Remove(filepath.Join(s.dir, IPsFile)); err != nil {
				s.t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(s.dir, IPsFile), 0700); err != nil {
				s.t.Fatal(err)
			}
		}, "blacklist.ips: not a regular file"},
		"run file is a directory": {func(s *stage) {
			if err := os.Remove(filepath.Join(s.dir, RunFile)); err != nil {
				s.t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(s.dir, RunFile), 0700); err != nil {
				s.t.Fatal(err)
			}
		}, "run: not a regular file"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newStage(t)
			prev := s.old()
			s.good()
			c.setup(s)
			cfg := s.cfg()
			cfg.Limits.MaxIPs = 2
			done := make(chan struct{})
			var res Result
			var err error
			go func() {
				res, err = Import(cfg)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Import did not return")
			}
			if !errors.Is(err, ErrRefused) || res.Imported || !strings.Contains(res.Refused, c.want) {
				t.Fatalf("Import: %+v %v, want refused with %q", res, err, c.want)
			}
			s.unchanged(prev)
			report := s.read(ReportFile)
			if !strings.HasPrefix(report, "FAIL stage: "+res.Refused) {
				t.Fatalf("report does not start with the refusal:\n%s", report)
			}
			for _, staged := range []string{"x.com", "flush", "secret", "other.example.com"} {
				if strings.Contains(report, staged) {
					t.Fatalf("report quotes the staged text %q:\n%s", staged, report)
				}
			}
		})
	}
}

func TestImportRefusesAFileOfADifferentOwner(t *testing.T) {
	s := newStage(t)
	prev := s.old()
	s.good()
	cfg := s.cfg()
	cfg.UID = os.Getuid() + 1
	res, err := Import(cfg)
	if !errors.Is(err, ErrRefused) || !strings.Contains(res.Refused, "not owned by pf-feeds") {
		t.Fatalf("Import: %+v %v", res, err)
	}
	s.unchanged(prev)
}

func TestImportRefusesAFileOverItsByteCap(t *testing.T) {
	was := listCap
	listCap = 20
	t.Cleanup(func() { listCap = was })
	s := newStage(t)
	prev := s.old()
	s.good()
	s.put(IPsFile, "1.2.3.1\n1.2.3.2\n1.2.3.3\n")
	res, err := Import(s.cfg())
	if !errors.Is(err, ErrRefused) || !strings.Contains(res.Refused, "blacklist.ips: larger than 20 bytes") {
		t.Fatalf("Import: %+v %v", res, err)
	}
	s.unchanged(prev)
}

func TestImportCutsALongReport(t *testing.T) {
	was := reportCap
	reportCap = 30
	t.Cleanup(func() { reportCap = was })
	s := newStage(t)
	s.good()
	s.put(ReportFile, "OK a: 1 ips\nOK b: 2 ips\nOK c: 3 ips\nOK d: 4 ips\n")
	if _, err := Import(s.cfg()); err != nil {
		t.Fatal(err)
	}
	if got := s.read(ReportFile); got != "OK a: 1 ips\nOK b: 2 ips\nOK c:\n" {
		t.Fatalf("report = %q", got)
	}
}

func TestImportNeedsTheRunOfThisRequest(t *testing.T) {
	for name, setup := range map[string]func(s *stage, c *Config){
		"other run":     func(s *stage, c *Config) { s.put(RunFile, strings.Repeat("0", 32)+"\n") },
		"no run file":   func(s *stage, c *Config) { _ = os.Remove(filepath.Join(s.dir, RunFile)) },
		"no newline":    func(s *stage, c *Config) { s.put(RunFile, s.run) },
		"bad config":    func(s *stage, c *Config) { c.Run = "" },
		"no stage":      func(s *stage, c *Config) { _ = os.RemoveAll(s.dir) },
		"stage is link": func(s *stage, c *Config) { _ = os.RemoveAll(s.dir); _ = os.Symlink(s.t.TempDir(), s.dir) },
	} {
		t.Run(name, func(t *testing.T) {
			s := newStage(t)
			prev := s.old()
			s.good()
			cfg := s.cfg()
			setup(s, &cfg)
			res, err := Import(cfg)
			if res.Imported || err == nil || errors.Is(err, ErrRefused) {
				t.Fatalf("Import: %+v %v", res, err)
			}
			if name != "stage is link" && !errors.Is(err, ErrNoRun) {
				t.Fatalf("err %v, want ErrNoRun", err)
			}
			s.unchanged(prev)
			if got := s.read(ReportFile); got != prev[ReportFile] {
				t.Fatalf("report changed: %q", got)
			}
		})
	}
}

func TestImportKeepsAListThatIsNotStaged(t *testing.T) {
	// All feeds failed: the stage has only the report and the run.
	s := newStage(t)
	prev := s.old()
	s.put(ReportFile, "FAIL hagezi: HTTP 503\n")
	res, err := Import(s.cfg())
	if err != nil || !res.Imported || res.IPs != -1 || res.Domains != -1 {
		t.Fatalf("Import: %+v %v", res, err)
	}
	for _, name := range []string{IPsFile, DomainsFile, SampleFile} {
		if got := s.read(name); got != prev[name] {
			t.Errorf("%s changed to %q", name, got)
		}
	}
	if got := s.read(ReportFile); got != "FAIL hagezi: HTTP 503\n" {
		t.Fatalf("report = %q", got)
	}
}

func TestWriteReportFilters(t *testing.T) {
	out := t.TempDir()
	if err := WriteReport(out, []string{"FAIL download: x\x1b[0m", "not a verb"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, ReportFile))
	if err != nil || string(b) != "FAIL download: x?[0m\n" {
		t.Fatalf("report = %q %v", b, err)
	}
}
