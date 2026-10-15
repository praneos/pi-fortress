package www

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeBin puts a script on PATH under name, so the claim script can be
// run for real against a curl that behaves however the test needs.
func fakeBin(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
}

// goodSetup is the setup.sh the claim in runClaimScript was issued for.
const goodSetup = "#!/bin/sh\nexit 0\n"

func runClaimScript(t *testing.T, curl string) (string, error) {
	t.Helper()
	home := t.TempDir()
	bin := t.TempDir()
	fakeBin(t, bin, "curl", curl)
	// The claim script runs setup.sh through sudo; the test only cares
	// what happens around it.
	fakeBin(t, bin, "sudo", "shift 2>/dev/null; cat >/dev/null 2>&1; exit 0")
	fakeBin(t, bin, "bash", "cat >/dev/null 2>&1; exit 0")
	script := filepath.Join(t.TempDir(), "claim.sh")
	body := ClaimScript("10.77.0.1", Claim{Code: "ABCD1234", Slot: "a1b2c3d4e5f67890", Kinds: []string{"GITHUB_TOKEN"},
		SetupSHA256: sum([]byte(goodSetup)), CASHA256: strings.Repeat("ab", 32)})
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", script)
	cmd.Env = append(os.Environ(), "HOME="+home, "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The claim script piped a download directly into a shell. /bin/sh has no
// pipefail, so the status of the pipeline is the status of the shell. A
// shell that gets no input exits 0. So a download that got a 404 or stopped
// half way did not trigger set -e. The script continued to write the
// placeholder files, and it printed "enrolled". The claim is one-time and
// is already spent at that point. So the next step for the operator is to
// enrol a box that never got its CA.
func TestClaimScriptFailsWhenTheDownloadFails(t *testing.T) {
	out, err := runClaimScript(t, "exit 22")
	if err == nil {
		t.Fatalf("the claim script succeeded with no setup.sh:\n%s", out)
	}
	if strings.Contains(out, "enrolled") {
		t.Fatalf("a failed download still reported enrolment:\n%s", out)
	}
}

// An empty body with a zero status is the same failure in a different
// form: a truncated transfer that the proxy closed cleanly.
func TestClaimScriptFailsWhenTheDownloadIsEmpty(t *testing.T) {
	out, err := runClaimScript(t, ": >\"$4\" 2>/dev/null; exit 0")
	if err == nil || strings.Contains(out, "enrolled") {
		t.Fatalf("an empty setup.sh enrolled anyway: err %v\n%s", err, out)
	}
}

// The full script must also still work.
func TestClaimScriptEnrolsWhenTheDownloadWorks(t *testing.T) {
	out, err := runClaimScript(t, "printf '#!/bin/sh\\nexit 0\\n' >\"$4\"; exit 0")
	if err != nil {
		t.Fatalf("claim script failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "enrolled") {
		t.Fatalf("a good run did not report enrolment:\n%s", out)
	}
}

// www is the only listener that the hostile agent can reach without a
// credential, and it had one deadline: the request headers. A client can
// send a header and then read nothing, or open connections and leave them.
// Each such client is a handler blocked on a write, plus a goroutine, with
// no bound on either.
func TestServerBoundsEveryPhaseOfARequest(t *testing.T) {
	s := &Server{Dir: t.TempDir()}
	srv := s.httpServer()
	for _, c := range []struct {
		name string
		got  time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout},
		{"ReadTimeout", srv.ReadTimeout},
		{"WriteTimeout", srv.WriteTimeout},
		{"IdleTimeout", srv.IdleTimeout},
	} {
		if c.got <= 0 {
			t.Errorf("%s is unset", c.name)
		}
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 1<<20 {
		t.Errorf("MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
}

// Deadlines bound the work of one connection. They do not bound the number
// of connections. The agent can open connections faster than they expire,
// so admission also needs a cap.
func TestListenerAdmitsOnlyAsManyConnectionsAsItSaid(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	ln := limitConns(base, 1, 0)
	addr := ln.Addr().String()

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	held, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("the listener accepted past its own limit")
	case <-time.After(100 * time.Millisecond):
	}
	held.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("a closed connection did not give its slot back")
	}
}

// The listener closes one address at its per-source cap at accept, but it
// still admits a different address. A closed connection gives the slot back
// to the address. The global cap is much higher, so only the per-source
// rule can explain a refusal.
func TestListenerCapsOneSourceNotOthers(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	ln := limitConns(base, 16, 1)
	addr := ln.Addr().String()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dialFrom := func(src string) net.Conn {
		t.Helper()
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: time.Second}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			t.Skipf("dial from %s: %v", src, err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	next := func() net.Conn {
		select {
		case c := <-accepted:
			return c
		case <-time.After(300 * time.Millisecond):
			return nil
		}
	}

	dialFrom("127.0.0.1")
	held := next()
	if held == nil {
		t.Fatal("first connection not accepted")
	}
	over := dialFrom("127.0.0.1")
	if c := next(); c != nil {
		c.Close()
		t.Fatal("a second connection from one address accepted past a cap of 1")
	}
	_ = over.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := over.Read(make([]byte, 1)); err == nil {
		t.Fatal("the refused connection was not closed")
	}
	dialFrom("127.0.0.2")
	if c := next(); c == nil {
		t.Fatal("another address refused while the first was at its cap")
	} else {
		c.Close()
	}
	held.Close()
	dialFrom("127.0.0.1")
	if c := next(); c == nil {
		t.Fatal("the address did not get its slot back after a close")
	} else {
		c.Close()
	}
}
