package dnsd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// isolatedBox is the agent listener and a paranoid desk. The allow list
// of the desk is at allow. A test leaves that file missing or writes it.
func isolatedBox(t *testing.T, isolate bool, allow string) (*Server, *upstream, error) {
	t.Helper()
	dir := t.TempDir()
	up := newUpstream(t, map[string][4]byte{"good.test": {1, 2, 3, 4}}, nil, 60)
	srv, err := New(Config{
		NFTTable:        "inet fortress",
		NFT:             &fakeNFT{},
		IsolateSegments: isolate,
		Segments: []Segment{
			{Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"), Upstream: up.addr(), NFTSet: "resolved_v4", LogPath: filepath.Join(dir, "agent.log")},
			{Name: "desk", Iface: "lo-desk", IP: netip.MustParseAddr("10.79.0.1"), Upstream: up.addr(), NFTSet: "resolved_desk_v4",
				LogPath: filepath.Join(dir, "desk.log"), Paranoid: true, AllowPath: allow},
		},
	})
	if err == nil {
		srv.logf = func(string, ...any) {}
		if err := srv.OpenLogs(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(srv.CloseLogs)
	}
	return srv, up, err
}

func rcodeOf(t *testing.T, srv *Server, seg int, name string) dnsmessage.RCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp := srv.answer(ctx, srv.segs[seg], netip.MustParseAddr("10.0.0.9"), query(t, name), 0)
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatalf("segment %d, %s: %v", seg, name, err)
	}
	return h.RCode
}

// Before, an unreadable file of one network stopped pf dns for every
// network: the daemon is one process, and it refused to start. Now, while
// the daemon runs, only the broken desk answers REFUSED. The agent
// continues to resolve.
func TestABrokenDeskDoesNotTakeTheAgentDown(t *testing.T) {
	srv, up, err := isolatedBox(t, true, filepath.Join(t.TempDir(), "allow.desk.domains"))
	if err != nil {
		t.Fatalf("the daemon refused to start over the desk's file: %v", err)
	}
	if rc := rcodeOf(t, srv, 0, "good.test"); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("agent: %v", rc)
	}
	if rc := rcodeOf(t, srv, 1, "good.test"); rc != dnsmessage.RCodeRefused {
		t.Fatalf("broken desk answered %v, want REFUSED", rc)
	}
	if n := up.asked.Load(); n != 1 {
		t.Fatalf("upstream asked %d times; the broken desk must forward nothing", n)
	}
	segs := strings.Join(srv.Segments(), "\n")
	if !strings.Contains(segs, "desk iface=lo-desk") || !strings.Contains(segs, "BROKEN=refusing-all(") {
		t.Fatalf("Segments does not show the desk broken:\n%s", segs)
	}
	if strings.Contains(strings.SplitN(segs, "\n", 2)[0], "BROKEN") {
		t.Fatalf("the agent is marked broken:\n%s", segs)
	}
}

// -check, and therefore apply, still refuses the configuration outright.
func TestCheckStaysStrictAboutASegmentFile(t *testing.T) {
	if _, _, err := isolatedBox(t, false, filepath.Join(t.TempDir(), "allow.desk.domains")); err == nil || !strings.Contains(err.Error(), "paranoid forward set") {
		t.Fatalf("strict start: %v", err)
	}
}

// The agent listener and the loopback stub of the box are never isolated.
// A failure of either one is a failure of the box. The box must not start
// quietly.
func TestTheAgentAndTheLoopbackStubAreNeverIsolated(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.conf")
	agent := func() Config {
		return Config{NFTTable: "inet fortress", NFT: &fakeNFT{}, IsolateSegments: true, Segments: []Segment{
			{Iface: "lo", IP: netip.MustParseAddr("10.77.0.1"), Upstream: "127.0.0.1:1", NFTSet: "resolved_v4", Paranoid: true, AllowPath: missing},
		}}
	}
	stub := func() Config {
		return Config{NFTTable: "inet fortress", NFT: &fakeNFT{}, IsolateSegments: true, Segments: []Segment{
			{Name: "pi", Iface: "lo", IP: netip.MustParseAddr("127.0.0.53"), Upstream: "127.0.0.1:1", Paranoid: true, AllowPath: missing},
		}}
	}
	for name, cfg := range map[string]func() Config{"agent": agent, "loopback stub": stub} {
		if _, err := New(cfg()); err == nil {
			t.Fatalf("the %s started without its list", name)
		}
	}
}

// The daemon serves a repaired desk on the next reload. If the file of a
// desk goes missing again, that desk keeps the list that it had. The
// others reload.
func TestReloadServesARepairedDeskAndKeepsAWorkingOne(t *testing.T) {
	allow := filepath.Join(t.TempDir(), "allow.desk.domains")
	srv, _, err := isolatedBox(t, true, allow)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allow, []byte("good.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(); err != nil {
		t.Fatalf("reload after the repair: %v", err)
	}
	if rc := rcodeOf(t, srv, 1, "good.test"); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("repaired desk answered %v", rc)
	}
	if strings.Contains(strings.Join(srv.Segments(), " "), "BROKEN") {
		t.Fatal("the repaired desk is still marked broken")
	}
	if err := os.Remove(allow); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(); err == nil || !strings.Contains(err.Error(), "reloaded without") {
		t.Fatalf("reload with the desk's file gone: %v", err)
	}
	if rc := rcodeOf(t, srv, 1, "good.test"); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("a working desk lost its list on a failed reload: %v", rc)
	}
	if rc := rcodeOf(t, srv, 0, "good.test"); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("agent after the partial reload: %v", rc)
	}
}

// logBox is the agent and a desk. Each one logs to the path that the test
// gives. The box uses the isolation of the running daemon.
func logBox(t *testing.T, agentLog, deskLog string) (*Server, error) {
	t.Helper()
	up := newUpstream(t, map[string][4]byte{"good.test": {1, 2, 3, 4}}, nil, 60)
	srv, err := New(Config{
		NFTTable:        "inet fortress",
		NFT:             &fakeNFT{},
		IsolateSegments: true,
		Segments: []Segment{
			{Iface: "lo", IP: netip.MustParseAddr("127.0.0.1"), Upstream: up.addr(), NFTSet: "resolved_v4", LogPath: agentLog},
			{Name: "desk", Iface: "lo-desk", IP: netip.MustParseAddr("10.79.0.1"), Upstream: up.addr(), NFTSet: "resolved_desk_v4", LogPath: deskLog},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.logf = func(string, ...any) {}
	return srv, srv.OpenLogs()
}

// Before, a desk log that did not open caused OpenLogs to fail. Thus pf
// dns did not start, and each reload after that failed. Now the desk runs
// without its log. It shows this in Segments and in the reload error. The
// first reload that can open the log starts to use it. The agent stays
// strict.
func TestADeskLogThatWillNotOpenCostsOnlyTheDesk(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0644); err != nil {
		t.Fatal(err)
	}
	agentLog := filepath.Join(dir, "agent.log")
	srv, err := logBox(t, agentLog, filepath.Join(blocker, "desk.log"))
	if err != nil {
		t.Fatalf("OpenLogs failed over the desk's log: %v", err)
	}
	t.Cleanup(srv.CloseLogs)
	segs := srv.Segments()
	if !strings.Contains(segs[1], "BROKEN=no-log(") || strings.Contains(segs[0], "BROKEN") {
		t.Fatalf("segments:\n%s", strings.Join(segs, "\n"))
	}
	if rc := rcodeOf(t, srv, 1, "good.test"); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("the desk without a log answered %v", rc)
	}
	if rc := rcodeOf(t, srv, 0, "good.test"); rc != dnsmessage.RCodeSuccess {
		t.Fatalf("agent: %v", rc)
	}
	if raw, _ := os.ReadFile(agentLog); !strings.Contains(string(raw), "good.test") {
		t.Fatalf("the agent's log lost its row: %q", raw)
	}
	if err := srv.Reload(); err == nil || !strings.Contains(err.Error(), "reloaded without") || !strings.Contains(err.Error(), `"desk"`) {
		t.Fatalf("reload with the desk's log still unopenable: %v", err)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blocker, 0755); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(); err != nil {
		t.Fatalf("reload once the desk's log can open: %v", err)
	}
	if strings.Contains(strings.Join(srv.Segments(), " "), "BROKEN") {
		t.Fatalf("still marked: %v", srv.Segments())
	}
	rcodeOf(t, srv, 1, "good.test")
	if raw, _ := os.ReadFile(filepath.Join(blocker, "desk.log")); !strings.Contains(string(raw), "good.test") {
		t.Fatalf("the desk's log after the repair: %q", raw)
	}
}

func TestTheAgentLogStaysStrict(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0644); err != nil {
		t.Fatal(err)
	}
	srv, err := logBox(t, filepath.Join(blocker, "agent.log"), filepath.Join(dir, "desk.log"))
	t.Cleanup(srv.CloseLogs)
	if err == nil {
		t.Fatal("the agent started without its log")
	}
}
