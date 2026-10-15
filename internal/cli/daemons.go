package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pi-fortress/internal/audit"
	"pi-fortress/internal/base"
	"pi-fortress/internal/blocklist"
	"pi-fortress/internal/broker"
	"pi-fortress/internal/ca"
	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/dnsd"
	"pi-fortress/internal/engine"
	"pi-fortress/internal/fakeip"
	"pi-fortress/internal/fence"
	"pi-fortress/internal/jsonl"
	"pi-fortress/internal/secrets"
	"pi-fortress/internal/www"
)

func signalCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func runEngine(args []string, _, stderr io.Writer) int {
	fs := newFlags("engine", stderr)
	listen := fs.String("listen", "", "agent-NIC ip:port, e.g. PI_IP:8080 (required; 0.0.0.0 and :: are refused)")
	var inspect listFlag
	fs.Var(&inspect, "inspect-listen", "ip:port of a segment with INSPECT=on, e.g. 10.79.0.1:8080; repeat it for each segment")
	sock := fs.String("sock", "/run/pi-fortress/broker/broker.sock", "broker unix socket")
	caPath := fs.String("ca", "/var/lib/pi-fortress/engine/ca.pem", "CA cert+key PEM")
	caCert := fs.String("ca-cert", "", "also write cert-only PEM (with -init-ca)")
	initCA := fs.Bool("init-ca", false, "create CA at -ca if missing, then exit")
	maxConns := fs.Int("max-conns", 256, "connection cap")
	// The limit for each agent address, inside -max-conns. Thus one agent
	// cannot take all slots and leave the others without HTTPS
	// (engine.DefaultMaxPerSource has the numbers). 0 disables it. It is a
	// flag, not only the const. Thus a box with one agent that crawls wide
	// can increase it through PF_ENGINE_FLAGS in engine.env without a
	// rebuild. The unit needs no change, because the default is here.
	maxPerIP := fs.Int("max-conns-per-ip", engine.DefaultMaxPerSource, "connections one source address may hold; 0 = no per-source cap")
	inspectPerIP := fs.Int("inspect-max-conns-per-ip", engine.DefaultInspectMaxPerSource, "the same cap on the -inspect-listen addresses; 0 = no per-source cap")
	handshake := fs.Duration("handshake", 10*time.Second, "handshake deadline")
	idle := fs.Duration("idle", 30*time.Second, "idle splice deadline")
	blockedPath := fs.String("blocked", "/etc/pi-fortress/blocked-domains.conf", "compiled domain block list (dnsmasq address= lines); missing is empty")
	paranoid := fs.Bool("paranoid", false, "paranoid mode: mint no leaf for an SNI outside the forward set (docs/paranoid_mode.md)")
	allowPath := fs.String("allow", "/etc/pi-fortress/allow.domains", "allow.domains path, with -paranoid")
	corePath := fs.String("core-hosts", "/etc/pi-fortress/core.hosts", "core.hosts path, with -paranoid: the host column only, never the kinds")
	labEcho := fs.Bool("lab-echo", false, "let pf-core-echo.test through the forward set (lab VM only)")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if *initCA {
		if err := ca.Init(*caPath, *caCert); err != nil {
			return fail(stderr, err)
		}
		log.Printf("pf engine ca %s", *caPath)
		return 0
	}
	// The same unicast-only rule that www has. The default was
	// 0.0.0.0:8080. Thus pf engine, when run by hand, listened on all
	// interfaces and minted leaves for all clients that reached it. Now
	// there is no default, and pf engine refuses the wildcard. The unit
	// passes ${PI_IP}:8080.
	if *listen == "" {
		return fail(stderr, errors.New("engine: -listen is required: the agent IP and port, e.g. 10.77.0.1:8080"))
	}
	for i, l := range append([]string{*listen}, inspect...) {
		flag := "-listen"
		if i > 0 {
			flag = "-inspect-listen"
		}
		host, _, err := net.SplitHostPort(l)
		if err == nil {
			err = base.CheckBindHost(host)
		}
		if err == nil && i > 0 && l == *listen {
			err = errors.New("it is the agent address")
		}
		if err != nil {
			return fail(stderr, fmt.Errorf("engine: %s %q: %w", flag, l, err))
		}
	}
	store, err := ca.Load(*caPath)
	if err != nil {
		return fail(stderr, err)
	}
	blocked, err := blocklist.Load(*blockedPath)
	if err != nil {
		return fail(stderr, err)
	}
	// When armed, these two files are the fence. A missing or unreadable
	// file causes an exit, not the empty set that the ordinary loaders give.
	// The type is the interface, so an off run keeps it nil. It does not
	// wrap a nil pointer, which would refuse each name.
	var forward engine.Forward
	if *paranoid {
		f, err := corepolicy.LoadForward(*allowPath, *corePath)
		if err != nil {
			return fail(stderr, fmt.Errorf("engine: -paranoid: %w", err))
		}
		forward = f
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail(stderr, err)
	}
	var lns []net.Listener
	for _, l := range inspect {
		sln, err := listenFreebind(l)
		if err != nil {
			ln.Close()
			for _, open := range lns {
				open.Close()
			}
			return fail(stderr, fmt.Errorf("engine: -inspect-listen %q: %w", l, err))
		}
		lns = append(lns, sln)
	}
	e := &engine.Engine{
		Sock:      *sock,
		CA:        store,
		Blocked:   blocked,
		Forward:   forward,
		LabEcho:   *labEcho,
		Handshake: *handshake,
		Idle:      *idle,
		MaxConns:  *maxConns,
	}
	// The struct reads 0 as "the default", the same as MaxConns. The flag
	// says that 0 is off. Thus off goes in as a negative value.
	e.MaxPerSource = *maxPerIP
	if *maxPerIP <= 0 {
		e.MaxPerSource = -1
	}
	e.InspectMaxPerSource = *inspectPerIP
	if *inspectPerIP <= 0 {
		e.InspectMaxPerSource = -1
	}
	ctx, stop := signalCtx()
	defer stop()
	log.Printf("pf engine %s sock=%s blocked=%d", strings.Join(append([]string{*listen}, inspect...), ","), *sock, blocked.Len())
	if *paranoid {
		log.Printf("pf engine: paranoid; forward set from %s and %s", *allowPath, *corePath)
	}
	if err := e.Serve(ctx, ln, lns...); err != nil && ctx.Err() == nil {
		return fail(stderr, err)
	}
	return 0
}

func runBroker(args []string, _, stderr io.Writer) int {
	fs := newFlags("broker", stderr)
	sock := fs.String("sock", "/run/pi-fortress/broker/broker.sock", "unix socket")
	adminSock := fs.String("admin-sock", "/run/pi-fortress/broker/admin.sock", "root-only unix socket for pf unlock; empty disables it")
	policy := fs.String("policy", "/etc/pi-fortress/core.hosts", "core.hosts path")
	rules := fs.String("rules", "/etc/pi-fortress/key_prefixes.rules", "token prefix rules")
	stripCore := fs.Bool("strip-core", true, "strip tokens of kinds a core host does not inject (off only for tools that must carry another provider's key to a core host)")
	allowPath := fs.String("allow", "/etc/pi-fortress/allow.domains", "allow.domains path")
	// The directory of the broker, not /etc/pi-fortress. apply.sh puts
	// secrets.env under BROKER_DIR, and the unit passes -secrets
	// explicitly. Thus production never used this default, and it became
	// stale. It is still important. DisabledPath gets the quarantine
	// sidecar from the directory of this path. Thus a broker that started
	// without the flag read one file and quarantined into a different file.
	secretsPath := fs.String("secrets", "/etc/pi-fortress/broker/secrets.env", "secrets.env")
	stripLog := fs.String("strip-log", "/var/log/pi-fortress/strip.jsonl", "strip jsonl")
	unknownLog := fs.String("unknown-log", "/var/log/pi-fortress/unknown.jsonl", "unknown jsonl")
	useLog := fs.String("use-log", "/var/log/pi-fortress/use.jsonl", "slot use jsonl (one line per slot per minute)")
	labEcho := fs.Bool("lab-echo", false, "enable pf-core-echo.test (reflects live tokens; lab VM only)")
	paranoid := fs.Bool("paranoid", false, "paranoid mode: refuse a Host or SNI outside allow.domains and the core.hosts host column (docs/paranoid_mode.md)")
	recompress := fs.Bool("recompress", true, "re-gzip inflated responses for clients that accepted gzip")
	// The allowance of the full broker for buffered bytes (broker.MemBudget;
	// membudget.go has the arithmetic). 0 keeps the built-in 256 MiB, sized
	// for GOMEMLIMIT=700MiB in the unit. It is a flag, so an operator who
	// increases the memory limits of the unit can increase this too, through
	// PF_BROKER_FLAGS, without a rebuild. Above it, bodies stream, responses
	// go out uncompressed, and the broker refuses what it must buffer.
	memBudgetMB := fs.Int64("mem-budget-mb", 0, "MB of buffers all connections together may hold; 0 = built-in 256")
	agentNet := fs.String("agent-net", "", "CIDR of the agent segment; connections from elsewhere are refused (required)")
	var fenceNets listFlag
	fs.Var(&fenceNets, "fence-net", "CIDR of a segment with INSPECT=on that the fence also serves; repeat it for each segment")
	maxConns := fs.Int("max-conns", 256, "connection cap, matches the engine")
	blockedPath := fs.String("blocked", "/etc/pi-fortress/blocked-domains.conf", "compiled domain block list (dnsmasq address= lines); missing is empty")
	gitPushPath := fs.String("git-push", "/etc/pi-fortress/git_push.allow", "git_push.allow: repos a git push may reach; missing or empty refuses every push (docs/git_push.md)")
	// The hourly budget for each slot (docs/fence.md 5.2d). Warn is armed by
	// default, because an alert costs an operator a glance. Stop is not
	// armed by default. A hard stop on a false positive kills a session that
	// works, and the operator knows the honest rate of their agent. Each 0
	// disables that threshold.
	warnRequests := fs.Int64("slot-warn-requests", 3000, "per-slot requests an hour before one operator alert; 0 off")
	stopRequests := fs.Int64("slot-stop-requests", 0, "per-slot requests an hour before the slot is quarantined; 0 off")
	warnUploadMB := fs.Int64("slot-warn-upload-mb", 500, "per-slot uploaded body MB an hour before one operator alert; 0 off")
	stopUploadMB := fs.Int64("slot-stop-upload-mb", 0, "per-slot uploaded body MB an hour before the slot is quarantined; 0 off")
	// Fake-IP (internal/fakeip): pf dns answers the agent from this pool
	// and writes the pairs to its journal. The broker maps an address back,
	// holds the SNI to it, and resolves the name itself. Empty is off. Off
	// gives the broker as it was before.
	fakeNet := fs.String("fakeip-net", "", "fake-IP pool prefix pf dns answers the agent from (e.g. 198.18.0.0/16); empty is off")
	fakeJournal := fs.String("fakeip-journal", "/var/lib/pi-fortress/dns/fakeip.journal", "fake-IP journal pf dns writes, with -fakeip-net")
	resolver := fs.String("resolver", "", "host:port of the DNS server for the broker's own fake-IP lookups; empty is the system resolver")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	for name, v := range map[string]int64{
		"slot-warn-requests":  *warnRequests,
		"slot-stop-requests":  *stopRequests,
		"slot-warn-upload-mb": *warnUploadMB,
		"slot-stop-upload-mb": *stopUploadMB,
		"mem-budget-mb":       *memBudgetMB,
	} {
		// Refused, not clamped: a negative value here is a typo in
		// net.env. If the code silently reads it as "off", the operator
		// thinks that a limit is armed.
		if v < 0 {
			return fail(stderr, fmt.Errorf("broker: -%s %d: not a count", name, v))
		}
	}
	// Above 1 TiB, the shift to bytes wraps negative. No Pi has 1 TiB.
	if *memBudgetMB > 1<<20 {
		return fail(stderr, fmt.Errorf("broker: -mem-budget-mb %d: more than 1 TiB", *memBudgetMB))
	}
	if *policy == "/etc/pi-fortress/core.hosts" {
		if _, err := os.Stat(*policy); err != nil {
			if _, err := os.Stat("/vagrant/vm/policy/core.hosts"); err == nil {
				*policy = "/vagrant/vm/policy/core.hosts"
				*rules = "/vagrant/vm/policy/key_prefixes.rules"
				*allowPath = "/vagrant/vm/policy/allow.domains"
				*gitPushPath = "/vagrant/vm/policy/git_push.allow"
			}
		}
	}
	gitPush, err := corepolicy.LoadGitPush(*gitPushPath)
	if err != nil {
		return fail(stderr, err)
	}
	pol, err := corepolicy.Load(*policy)
	if err != nil {
		return fail(stderr, err)
	}
	tr, err := fence.LoadTokenRules(*rules)
	if err != nil {
		return fail(stderr, err)
	}
	if err := tr.Streamable(); err != nil {
		return fail(stderr, err)
	}
	if _, err := os.Stat(*secretsPath); err != nil {
		return fail(stderr, fmt.Errorf("secrets.env missing: %s", *secretsPath))
	}
	store := secrets.Open(*secretsPath)
	logSecretsState(store)
	allow, err := corepolicy.LoadDomains(*allowPath)
	if err != nil {
		return fail(stderr, err)
	}
	for h := range pol.Hosts {
		allow[h] = struct{}{}
	}
	// When armed, both files are the fence itself. A missing or unreadable
	// file causes an exit, not the empty set that LoadDomains and Load give.
	var forward *corepolicy.Forward
	if *paranoid {
		if forward, err = corepolicy.LoadForward(*allowPath, *policy); err != nil {
			return fail(stderr, fmt.Errorf("broker: -paranoid: %w", err))
		}
	}
	blocked, err := blocklist.Load(*blockedPath)
	if err != nil {
		return fail(stderr, err)
	}
	b := &broker.Broker{
		Policy:     pol,
		Blocked:    blocked,
		Store:      store,
		TokenRE:    tr.All(),
		Rules:      tr,
		StripCore:  *stripCore,
		AllowHosts: allow,
		Logs:       &jsonl.Writer{StripPath: *stripLog, UnknownPath: *unknownLog, UsePath: *useLog},
		LabEcho:    *labEcho,
		Paranoid:   *paranoid,
		Forward:    forward,
		GitPush:    gitPush,
		Recompress: *recompress,
		MemBudget:  *memBudgetMB << 20,
		Budget: broker.SlotBudget{
			WarnRequests: *warnRequests,
			StopRequests: *stopRequests,
			WarnBytes:    *warnUploadMB << 20,
			StopBytes:    *stopUploadMB << 20,
		},
	}
	if *fakeNet != "" {
		fp, err := netip.ParsePrefix(*fakeNet)
		if err == nil {
			err = fakeip.CheckPrefix(fp)
		}
		if err != nil {
			return fail(stderr, fmt.Errorf("broker: -fakeip-net %q: %w", *fakeNet, err))
		}
		if *fakeJournal == "" {
			return fail(stderr, errors.New("broker: -fakeip-net needs -fakeip-journal"))
		}
		b.FakeIP = fakeip.NewTable(fp, *fakeJournal)
		b.Resolve = broker.NewResolver(*resolver)
		log.Printf("pf broker: fake-ip %s from %s, resolver %q", fp, *fakeJournal, *resolver)
	}
	pfx, err := netip.ParsePrefix(*agentNet)
	if err != nil {
		return fail(stderr, fmt.Errorf("broker: -agent-net %q: %w", *agentNet, err))
	}
	b.AgentNet = pfx
	for _, n := range fenceNets {
		fp, err := netip.ParsePrefix(n)
		if err != nil {
			return fail(stderr, fmt.Errorf("broker: -fence-net %q: %w", n, err))
		}
		if fp.Overlaps(pfx) {
			return fail(stderr, fmt.Errorf("broker: -fence-net %s overlaps -agent-net %s", fp, pfx))
		}
		b.FenceNets = append(b.FenceNets, fp.Masked())
	}
	if *maxConns <= 0 {
		*maxConns = 256
	}
	if *labEcho {
		log.Print("pf broker: lab echo enabled; pf-core-echo.test reflects live tokens")
	}
	if *paranoid {
		log.Printf("pf broker: paranoid; forward set from %s and %s", *allowPath, *policy)
	}
	// Log this at start, because the hour is in memory. After a restart,
	// the journal is the only record of the limits. It is also the only
	// record that the count started again here.
	log.Printf("pf broker: slot budget per hour: warn %d requests / %d MB, stop %d requests / %d MB (0 is off)",
		*warnRequests, *warnUploadMB, *stopRequests, *stopUploadMB)
	_ = os.Remove(*sock)
	if err := os.MkdirAll(filepath.Dir(*sock), 0750); err != nil {
		return fail(stderr, err)
	}
	ln, err := net.Listen("unix", *sock)
	if err != nil {
		return fail(stderr, err)
	}
	_ = os.Chmod(*sock, 0660)
	ctx, stop := signalCtx()
	defer stop()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go b.WatchExpiry(ctx, time.Hour)
	if *adminSock != "" {
		if err := serveAdmin(ctx, *adminSock, b); err != nil {
			return fail(stderr, err)
		}
	}
	log.Printf("pf broker %s", *sock)
	acceptCapped(ctx, ln, *maxConns, "broker", func(c net.Conn) error {
		return b.Handle(ctx, c)
	})
	return 0
}

// logSecretsState logs a faulted or sealed store one time at startup. Do
// not let the operator find it from a refused request some hours later.
// A sealed store is not a reason to refuse to start. The fence, the
// segments and the ruleset do not depend on it. Only substitution waits.
func logSecretsState(store *secrets.Store) {
	st, err := store.State()
	if err != nil {
		log.Printf("pf broker: secrets: %v", err)
		return
	}
	switch {
	case st.Fault != "":
		log.Printf("pf broker: secrets FAULT: %s; every substitution will be refused", st.Fault)
	case st.Sealed:
		log.Print("pf broker: secrets sealed; substitution is refused until pf unlock")
	}
}

// serveAdmin opens the admin socket of the broker and serves it until ctx
// ends.
func serveAdmin(ctx context.Context, adminSock string, b *broker.Broker) error {
	// A second listener, on purpose not the broker socket. The engine
	// dials that one, and the engine handles untrusted agent traffic.
	// The verb that gives the broker its key must not be reachable
	// from there. 0600 keeps the fence out. Root still connects,
	// because root bypasses DAC.
	admin := &broker.Admin{Store: b.Store, Budget: b.BudgetHour}
	_ = os.Remove(adminSock)
	// Listen creates the inode under UMask=0007 of the unit. Thus the
	// inode is 0770 until the chmod below. The check for connect(2)
	// occurs at connect time: a dial queued in that window is accepted
	// after the chmod. Make the mask narrower, so the inode is 0600 at
	// creation. The mask is process-wide. Nothing else creates a file
	// here, because the accept loops have not started.
	mask := syscall.Umask(0o077)
	aln, err := net.Listen("unix", adminSock)
	syscall.Umask(mask)
	if err != nil {
		return err
	}
	if err := os.Chmod(adminSock, 0600); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		aln.Close()
	}()
	go acceptCapped(ctx, aln, adminMaxConns, "broker admin", func(c net.Conn) error {
		return admin.Serve(ctx, c)
	})
	log.Printf("pf broker admin %s", adminSock)
	return nil
}

// adminMaxConns caps the open connections of the admin socket. Its
// clients are pf unlock from one operator and the budget reads of the
// tui, a few at one time. The socket is root-only, so this is not a
// defence against the agent. It stops a root process that misbehaves
// (a loop that dials pf unlock) from an increase of the broker
// goroutines past TasksMax=512 of the unit. That would kill the fence.
// The uncapped loop beside the capped broker loop allowed this. 16 is
// several times honest use, and leaves room for the 256 agent slots.
const adminMaxConns = 16

// acceptCapped accepts on ln until ctx ends. It serves each connection
// on its own goroutine, at most max at one time. It closes and logs one
// more connection past that limit immediately. A caller that retries gets
// in when a slot becomes free. A flood costs an accept and a close, not a
// goroutine.
func acceptCapped(ctx context.Context, ln net.Listener, max int, what string, serve func(net.Conn) error) {
	sem := make(chan struct{}, max)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Print(err)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Printf("%s: max_conns=%d drop", what, max)
			c.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			if err := serve(c); err != nil {
				log.Print(err)
			}
		}()
	}
}

func runWWW(args []string, _, stderr io.Writer) int {
	fs := newFlags("www", stderr)
	listen := fs.String("listen", "", "ip:port (default PI_IP:80 from net.env)")
	dir := fs.String("dir", "", "directory with setup.sh and ca.pem")
	initLedger := fs.Bool("init-ledger", false, "make or repair claims/ledger.jsonl 0660 in the claims directory's group, then exit")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	s := www.Defaults()
	if *initLedger {
		d := s.Dir
		if *dir != "" {
			d = *dir
		}
		if err := www.InitLedger(www.ClaimsDir(d)); err != nil {
			return fail(stderr, err)
		}
		return 0
	}
	// On a Pi, this write is refused, and the redeem goes to the ledger
	// only. vm/pi/www.service runs DynamicUser with ProtectSystem=strict
	// and names one ReadWritePaths: the claims directory. Thus /var/log is
	// read-only to it. This is on purpose: keep the audit log out of
	// ReadWritePaths. This is the one listener that an agent reaches without
	// a credential, so the file that records each admin action stays
	// writable by root only. The redeem is in claims/ledger.jsonl. It goes
	// in the audit log only where root runs www. audit.Log discards a
	// write that it cannot make. It does not fail a handoff that the agent
	// waits for.
	s.Audit = audit.Default()
	if *dir != "" {
		s.Dir = *dir
	}
	if *listen != "" {
		host, portStr, err := net.SplitHostPort(*listen)
		if err != nil {
			return fail(stderr, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fail(stderr, fmt.Errorf("www: bad port %q", portStr))
		}
		s.Bind = host
		s.Port = port
	}
	if s.Bind == "" {
		return fail(stderr, fmt.Errorf("www: PI_IP missing"))
	}
	ctx, stop := signalCtx()
	defer stop()
	if err := s.Serve(ctx); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// runDNS is the resolver. dnsmasq no longer has a DNS half.
//
// -config FILE is the only way in: the segment list that apply writes.
// The project removed the single-segment flags of phase 1 together with
// the GO_DNS key.
// After apply moved to the file, nothing on a box set them. An untested
// second way to configure the only resolver of the box is a liability,
// not an option.
func runDNS(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("dns", stderr)
	configPath := fs.String("config", "", "segment list as JSON")
	check := fs.Bool("check", false, "validate the configuration and exit, binding nothing")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if *configPath == "" {
		return fail(stderr, errors.New("pf dns: -config FILE is required"))
	}
	return runDNSConfig(*configPath, *check, stdout, stderr)
}

// runDNSConfig is the -config arm: the same daemon, a segment list read
// from a file instead of one segment read from flags.
func runDNSConfig(path string, check bool, stdout, stderr io.Writer) int {
	f, err := os.Open(path)
	if err != nil {
		return fail(stderr, fmt.Errorf("-config: %w", err))
	}
	cfg, err := dnsd.ParseConfig(f)
	f.Close()
	if err != nil {
		return fail(stderr, err)
	}
	// At run time, an unreadable file of one segment costs only that
	// segment. -check stays strict, so apply refuses the full configuration.
	cfg.IsolateSegments = !check
	srv, err := dnsd.New(cfg)
	if err != nil {
		return fail(stderr, err)
	}
	return serveDNS(srv, check, fmt.Sprintf("pf dns %d segments on :%d", len(cfg.Segments), cfg.Listen), stdout, stderr)
}

// serveDNS is -check and the run loop. They share it, so the two ways
// to configure the daemon cannot become different in how they start
// it. A -check that took a different path from the run has no value.
func serveDNS(srv *dnsd.Server, check bool, banner string, stdout, stderr io.Writer) int {
	if check {
		for _, line := range srv.Segments() {
			fmt.Fprintln(stdout, line)
		}
		return 0
	}
	ctx, stop := signalCtx()
	defer stop()
	// dnsmasq read SIGHUP as "read the lists again". The dns.reload of
	// pf tui still sends it.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			if err := srv.Reload(); err != nil {
				log.Printf("pf dns reload: %v", err)
			}
		}
	}()
	log.Printf("%s %s", banner, strings.Join(srv.Segments(), " "))
	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		return fail(stderr, err)
	}
	return 0
}

// listFlag collects each use of a flag that may repeat. A duplicate value
// is refused: a second listen on the same address fails late, at bind.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	if slices.Contains(*l, v) {
		return fmt.Errorf("%q is given twice", v)
	}
	*l = append(*l, v)
	return nil
}

// listenFreebind binds a segment address with IP_FREEBIND. A desk cable
// that is out at boot, or a VLAN that comes up after the engine, must not
// stop the fence of the agent network. The listener gets traffic when the
// address arrives. The agent address stays strict: without it, the engine
// has no work, and systemd must show the failure.
func listenFreebind(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp", addr)
}
