package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"syscall"

	"pi-fortress/internal/netgate"
)

const netgateUsage = "usage: pf netgate run|ping [-config FILE] [-set NAME]"

// runNetgate is pf netgate. run is the daemon (pi-fortress-netgate.service).
// ping is one GATE request with no address, as the current user: it shows
// whether this account reaches netgate and passes its peer check.
func runNetgate(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("netgate", stderr)
	config := fs.String("config", "/etc/pi-fortress/dns.json", "run: the segment list of pf dns (nft table, gate sets, SNI queues)")
	set := fs.String("set", "resolved_v4", "ping: the gate set that the request names")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	verb, code, ok := verbArgs(fs, stderr, netgateUsage)
	if !ok {
		return code
	}
	switch verb {
	case "run":
		return runNetgateDaemon(*config, stderr)
	case "ping":
		if err := netgate.Ping(netgate.DNSSocket, *set); err != nil {
			return fail(stderr, fmt.Errorf("pf netgate ping: %w", err))
		}
		fmt.Fprintln(stdout, "pf netgate: ok")
		return 0
	default:
		fmt.Fprintln(stderr, netgateUsage)
		return 2
	}
}

func runNetgateDaemon(config string, stderr io.Writer) int {
	// The sockets must not be open to anyone before listen sets their
	// group (the unit also has UMask=0077).
	syscall.Umask(0o077)
	f, err := os.Open(config)
	if err != nil {
		return fail(stderr, fmt.Errorf("pf netgate: %w", err))
	}
	dc, skipped, err := netgate.ParseDNSConfig(f)
	f.Close()
	if err != nil {
		return fail(stderr, fmt.Errorf("pf netgate: %s: %w", config, err))
	}
	for _, s := range skipped {
		log.Printf("pf netgate: %s names set %q, which is not a resolver gate set; GATE refuses it", config, s)
	}
	dns, err := netgate.LookupPeer(netgate.DNSUser, netgate.DNSGroup)
	if err != nil {
		return fail(stderr, fmt.Errorf("pf netgate: the agent resolver account: %w", err))
	}
	ct, err := netgate.LookupPeer(netgate.CTUser, netgate.CTUserGroup)
	if err != nil {
		return fail(stderr, fmt.Errorf("pf netgate: the observe account: %w", err))
	}
	ctGroup, err := netgate.LookupGroup(netgate.CTGroup)
	if err != nil {
		return fail(stderr, fmt.Errorf("pf netgate: the group of ct.sock: %w", err))
	}
	srv, err := netgate.New(netgate.Config{
		Dir:       netgate.Dir,
		DNSConfig: dc,
		DNS:       dns,
		DNSGroup:  int(dns.GID),
		CT:        ct,
		CTGroup:   ctGroup,
	})
	if err != nil {
		return fail(stderr, err)
	}
	ctx, stop := signalCtx()
	defer stop()
	log.Printf("pf netgate: table %q, gate sets %v, SNI queues %v", dc.Table, dc.Sets, dc.Queues)
	if err := srv.Run(ctx); err != nil {
		return fail(stderr, err)
	}
	return 0
}
