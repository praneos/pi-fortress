package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"pi-fortress/internal/alert"
	"pi-fortress/internal/audit"
	"pi-fortress/internal/base"
	"pi-fortress/internal/enroll"
	"pi-fortress/internal/fetch"
	"pi-fortress/internal/observe"
	"pi-fortress/internal/policycompile"
)

// verbArgs completes the parse that flag.Parse stops, the same way that
// checkApplyArgs examines the full invocation before apply acts on it.
// flag stops at the first word that is not a flag (the subcommand).
// Before, all words after it were discarded: pf monitor once -n 5 showed
// ten rows, and pf observe show -h ran show and did not print the help.
// This parses the tail of the argv as flags. Thus a flag works at each
// position where the operator typed it, and a word that is not a flag is
// refused. No verb in this file reads a positional after the
// subcommand itself.
func verbArgs(fs *flag.FlagSet, stderr io.Writer, usage string) (string, int, bool) {
	name := fs.Arg(0)
	if fs.NArg() > 1 {
		rest := append([]string(nil), fs.Args()[1:]...)
		if code, ok := parse(fs, rest); !ok {
			return "", code, false
		}
		if fs.NArg() > 0 {
			code, ok := surplusArg(fs, stderr, usage)
			return "", code, ok
		}
	}
	return name, 0, true
}

// noVerbArgs is verbArgs for the two verbs that take no subcommand at all,
// where any positional is a typo.
func noVerbArgs(fs *flag.FlagSet, stderr io.Writer, usage string) (int, bool) {
	if fs.NArg() > 0 {
		return surplusArg(fs, stderr, usage)
	}
	return 0, true
}

func surplusArg(fs *flag.FlagSet, stderr io.Writer, usage string) (int, bool) {
	fmt.Fprintf(stderr, "%s: unknown argument %q\n", fs.Name(), fs.Arg(0))
	fmt.Fprintln(stderr, usage)
	return 2, false
}

// logTool records a change from a pf subcommand that has no verb behind
// it. admin.CallCtx records all other mutations. But fetch and compile
// are their own entry points and never reach it. Thus, when the fence of
// a box started to drop different traffic, the log did not show which
// run rewrote the lists. The caller builds Args. It does not come from
// the flag set. This is the same allow-list discipline as
// admin.Args.fields(): a field that nobody named cannot be written,
// whatever a future flag carries.
func logTool(verb string, args map[string]string, took time.Duration, err error) {
	e := audit.Entry{
		Verb:  verb,
		Role:  "admin",
		Actor: audit.Actor(os.Getenv, os.Getuid()),
		Args:  args,
		OK:    err == nil,
		MS:    took.Milliseconds(),
	}
	if err != nil {
		e.Err = err.Error()
	}
	_ = audit.Default().Append(e)
}

const fetchUsage = "usage: pf fetch [-policy DIR] [-out DIR]"

const compileUsage = "usage: pf compile --policy DIR --out-nft FILE --out-dns FILE [--out-doh-nft FILE] [--out-doh-dns FILE] [--out-house-dns FILE] [--out-house-doh-dns FILE] [--out-house-private-dns-nft FILE] [--out-direct-nft FILE] [--out-house-direct-nft FILE] [--out-house-whatsapp-nft FILE] [--out-ssh-nft FILE] [--out-domain-map FILE] [--out-ip-map FILE]"

const observeUsage = "usage: pf observe once|run|show|reset"

const alertUsage = "usage: pf alert run|show|once|watch|wg"

func runFetch(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("fetch", stderr)
	policy := fs.String("policy", "", "policy directory")
	out := fs.String("out", "", "generated output directory")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if code, ok := noVerbArgs(fs, stderr, fetchUsage); !ok {
		return code
	}
	p := *policy
	if p == "" {
		p = base.PolicyDir()
	}
	o := *out
	if o == "" {
		o = filepath.Join(p, "generated")
	}
	f := fetch.Defaults(p, o)
	start := time.Now()
	report, nIPs, nDoms, err := f.Run()
	fields := map[string]string{
		"policy": p, "out": o,
		"ips": strconv.Itoa(nIPs), "domains": strconv.Itoa(nDoms),
	}
	// Run returns a nil error when some feeds answered and some did not.
	// Thus OK alone would audit a partial fetch as a clean one. The entry
	// has the count, because nobody reads fetch.report without a prompt.
	fails, stale, truncated := fetch.CountWarnings(report)
	if fails > 0 {
		fields["fails"] = strconv.Itoa(fails)
	}
	if stale > 0 {
		fields["stale"] = strconv.Itoa(stale)
	}
	if truncated > 0 {
		fields["truncated"] = strconv.Itoa(truncated)
	}
	logTool("fetch", fields, time.Since(start), err)
	for _, line := range report {
		fmt.Fprintln(stdout, line)
	}
	fmt.Fprintf(stdout, "wrote %d ips, %d domains -> %s\n", nIPs, nDoms, o)
	if err != nil {
		return 1
	}
	return 0
}

func runCompile(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("compile", stderr)
	policy := fs.String("policy", "", "policy directory")
	outNFT := fs.String("out-nft", "", "nft elements path")
	outDNS := fs.String("out-dns", "", "dnsmasq sinkhole path")
	outDoHNFT := fs.String("out-doh-nft", "", "DoH nft elements path")
	outDoHDNS := fs.String("out-doh-dns", "", "DoH dnsmasq path")
	outHouseDNS := fs.String("out-house-dns", "", "house-only dnsmasq sinkhole path (ads, trackers)")
	outHouseVPNDNS := fs.String("out-house-vpn-dns", "", "house VPN/proxy feed sinkhole path, served while HOUSE_BLOCK_VPN is on")
	outHouseDoHDNS := fs.String("out-house-doh-dns", "", "DoH sinkhole path minus house_private_dns.domains")
	outHousePrivateNFT := fs.String("out-house-private-dns-nft", "", "house_private_dns.ips nft elements path")
	outDirectNFT := fs.String("out-direct-nft", "", "direct_ip.allow nft elements path")
	outHouseDirectNFT := fs.String("out-house-direct-nft", "", "house_direct_ip.allow nft elements path")
	outHouseWhatsAppNFT := fs.String("out-house-whatsapp-nft", "", "house_whatsapp.ips nft elements path")
	outSSHNFT := fs.String("out-ssh-nft", "", "ssh_allow.ips nft elements path")
	outDomainMap := fs.String("out-domain-map", "", "sinkhole name → feed map path (name<TAB>feed)")
	outIPMap := fs.String("out-ip-map", "", "blacklist prefix → feed map path (prefix<TAB>feed)")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if code, ok := noVerbArgs(fs, stderr, compileUsage); !ok {
		return code
	}
	if *policy == "" || *outNFT == "" || *outDNS == "" {
		fmt.Fprintln(stderr, compileUsage)
		return 2
	}
	start := time.Now()
	sum, err := policycompile.Compile(*policy, policycompile.Out{
		NFT:                *outNFT,
		DNS:                *outDNS,
		DoHNFT:             *outDoHNFT,
		DoHDNS:             *outDoHDNS,
		HouseDNS:           *outHouseDNS,
		HouseVPNDNS:        *outHouseVPNDNS,
		HouseDoHDNS:        *outHouseDoHDNS,
		HousePrivateDNSNFT: *outHousePrivateNFT,
		DirectIPNFT:        *outDirectNFT,
		HouseDirectIPNFT:   *outHouseDirectNFT,
		HouseWhatsAppNFT:   *outHouseWhatsAppNFT,
		SSHAllowNFT:        *outSSHNFT,
		DomainMap:          *outDomainMap,
		IPMap:              *outIPMap,
	})
	// The two counts are the purpose of the entry. The paths show which
	// files were rewritten. The counts show by how much. That pair shows
	// the difference between a compile that made the blocklist empty
	// and a compile that did its job.
	logTool("compile", map[string]string{
		"policy": *policy, "out-nft": *outNFT, "out-dns": *outDNS,
		"ips": strconv.Itoa(sum.IPs), "domains": strconv.Itoa(sum.Domains),
	}, time.Since(start), err)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, sum.Line())
	return 0
}

func runObserve(args []string, _, stderr io.Writer) int {
	fs := newFlags("observe", stderr)
	interval := fs.Int("interval", 10, "run loop seconds")
	state := fs.String("state", "", "observe.json")
	dnsLog := fs.String("dnslog", "", "resolver query log (default /var/log/pi-fortress/dns.jsonl)")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	verb, code, ok := verbArgs(fs, stderr, observeUsage)
	if !ok {
		return code
	}
	// Env: PF_OBSERVE_FLUSH_BYTES (10485760) and PF_OBSERVE_FLUSH_INTERVAL
	// (15m) limit how long rows and state stay in memory before a write.
	// PF_OBSERVE_VOLUME_MB (500) is the amount in one hour that one client
	// can send to one destination before a volume alert.
	// PF_OBSERVE_TUNNEL_NAMES (120) is the number of distinct names in one
	// minute under one domain that the DNS tunnel heuristic calls enough.
	// PF_OBSERVE_VOLUME_MB=0 disables the volume alert.
	// PF_OBSERVE_TUNNEL_NAMES=0 disables the DNS tunnel heuristic.
	o := observe.Defaults()
	o.Stderr = stderr
	o.Interval = time.Duration(*interval) * time.Second
	if *state != "" {
		o.StatePath = *state
	}
	if *dnsLog != "" {
		o.DNSLog = *dnsLog
	}
	ctx, stop := signalCtx()
	defer stop()
	switch verb {
	case "show":
		o.Show(o.Load())
	case "once":
		if err := o.Once(); err != nil {
			return fail(stderr, err)
		}
	case "reset":
		if err := o.Reset(); err != nil {
			return fail(stderr, err)
		}
	case "run":
		if err := o.Run(ctx); err != nil {
			return fail(stderr, err)
		}
	default:
		fmt.Fprintln(stderr, observeUsage)
		return 2
	}
	return 0
}

func runAlert(args []string, _, stderr io.Writer) int {
	fs := newFlags("alert", stderr)
	strip := fs.String("strip", "", "strip.jsonl path")
	offset := fs.String("offset", "", "offset file")
	last := fs.String("last", "", "last event file")
	policy := fs.String("policy", "", "directory containing alert.url")
	ifname := fs.String("if", "wg0", "wireguard interface for alert wg")
	maxAge := fs.Duration("max", 3*time.Minute, "handshake age that counts as down")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	verb, code, ok := verbArgs(fs, stderr, alertUsage)
	if !ok {
		return code
	}
	a := alert.Defaults()
	a.Stderr = stderr
	if *strip != "" {
		a.StripLog = *strip
	}
	if *offset != "" {
		a.OffsetPath = *offset
	}
	if *last != "" {
		a.LastPath = *last
	}
	if *policy != "" {
		a.PolicyDirs = []string{*policy}
	}
	ctx, stop := signalCtx()
	defer stop()
	switch verb {
	case "show":
		return a.Show()
	case "once":
		return a.Once()
	case "watch":
		if err := a.Watch(ctx); err != nil {
			return fail(stderr, err)
		}
	case "run":
		if err := a.Run(ctx); err != nil {
			return fail(stderr, err)
		}
	case "wg":
		return a.WGOnce(*ifname, *maxAge)
	default:
		fmt.Fprintln(stderr, alertUsage)
		return 2
	}
	return 0
}

func runEnroll(args []string, stdout, stderr io.Writer) int {
	return enroll.Main(args, stdout, stderr)
}
