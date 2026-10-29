package observe

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pi-fortress/internal/netgate"
)

// The daemon reads conntrack through pf netgate, not through a fork of
// its own. When netgate is down, the flow rows stop, one line says why,
// and one line says when it answers again.
func TestConntrackThroughNetgate(t *testing.T) {
	dir, err := os.MkdirTemp("", "obsng")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	fake := filepath.Join(dir, "conntrack")
	script := "#!/bin/sh\n" +
		"[ \"$1\" = -L ] || exit 2\n" +
		"echo 'ipv4     2 tcp      6 117 TIME_WAIT src=10.77.0.10 dst=172.66.147.243 sport=51234 dport=443 packets=6 bytes=517 src=172.66.147.243 dst=10.77.0.10 sport=443 dport=51234 packets=5 bytes=4321 [ASSURED] mark=0 use=1'\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "net.env")
	if err := os.WriteFile(env, []byte("AGENT_NET=10.77.0.0/24\nPI_IP=10.77.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	clock := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	o := &Observer{
		StatePath:  filepath.Join(dir, "observe.json"),
		JSONLPath:  filepath.Join(dir, "observe.jsonl"),
		DNSLog:     filepath.Join(dir, "missing.log"),
		OffsetPath: filepath.Join(dir, "off"),
		CTPath:     filepath.Join(dir, "missing-ct"),
		CTSocket:   filepath.Join(dir, "ct.sock"),
		// Never used while CTSocket is set: the daemon has no capability.
		CTCmd:      []string{fake, "-L", "-o", "extended"},
		NetEnvPath: []string{env},
		Stderr:     &stderr,
		Now:        func() time.Time { return clock },
	}
	key := "10.77.0.10>172.66.147.243:443/tcp"

	// netgate is down.
	for range 2 {
		if st := o.Snapshot(); len(st.Flows) != 0 {
			t.Fatalf("flows with no netgate: %+v", st.Flows)
		}
	}
	if n := strings.Count(stderr.String(), "conntrack through netgate:"); n != 1 {
		t.Fatalf("%d lines for one reason, want 1:\n%s", n, stderr.String())
	}

	me := netgate.Peer{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	srv, err := netgate.New(netgate.Config{
		Dir:       dir,
		DNSConfig: netgate.DNSConfig{Table: "inet fortress"},
		DNS:       me, DNSGroup: os.Getgid(),
		CT: me, CTGroup: os.Getgid(),
		CTArgv: []string{fake, "-L", "-o", "extended"},
		Logf:   t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	var st *State
	for range 300 {
		if st = o.Snapshot(); st.Flows[key] != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st.Flows[key] == nil || st.Flows[key].Bytes != 4838 {
		t.Fatalf("no flow through netgate: %+v\n%s", st.Flows, stderr.String())
	}
	if !strings.Contains(stderr.String(), "conntrack through netgate answers again") {
		t.Fatalf("no line for the recovery:\n%s", stderr.String())
	}
}
