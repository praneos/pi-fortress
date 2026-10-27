package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"pi-fortress/internal/render"
)

// pf render is the read-and-refuse half of apply. It reads the net.env
// values from the environment (apply.sh has just sourced that file),
// house.env, segments.d and the compiled element files. It writes the
// ruleset and the variables that apply.sh continues with.
func runRender(args []string, _, stderr io.Writer) int {
	fs := newFlags("render", stderr)
	houseEnv := fs.String("house-env", "/etc/pi-fortress/house.env", "house segment file")
	segDir := fs.String("segments-dir", "/etc/pi-fortress/segments.d", "plain segment files")
	intIF := fs.String("int-if", "", "agent interface (default: INT_IF from net.env, else detected with --live, else eth0)")
	wanIF := fs.String("wan-if", "", "uplink interface (default: WAN_IF from net.env, else detected with --live, else wlan0)")
	live := fs.Bool("live", false, "real apply: detect interfaces, require the pf-dns account when DoT is on")
	paranoid := fs.Bool("paranoid", false, "paranoid mode: the agent gate stops carving @direct_ip_v4 out of its drop")
	elems := fs.String("elements", "", "blacklist nft elements file")
	dohElems := fs.String("doh-elements", "", "DoH nft elements file")
	directElems := fs.String("direct-elements", "", "direct_ip nft elements file")
	houseDirectElems := fs.String("house-direct-elements", "", "house_direct_ip nft elements file")
	privElems := fs.String("house-private-dns-elements", "", "house_private_dns nft elements file")
	waElems := fs.String("house-whatsapp-elements", "", "house_whatsapp nft elements file")
	sshElems := fs.String("ssh-elements", "", "ssh_allow nft elements file")
	ntpPassElems := fs.String("ntp-pass-elements", "", "ntp_pass nft elements file")
	outNFT := fs.String("out-nft", "", "nftables.conf path")
	outEnv := fs.String("out-env", "", "derived variables path, sourced by apply.sh")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if *outNFT == "" || *outEnv == "" {
		fmt.Fprintln(stderr, "usage: pf render --out-nft FILE --out-env FILE [--house-env FILE] [--segments-dir DIR] [--int-if IF --wan-if IF] [--live] [--paranoid] [--elements FILE] [--doh-elements FILE] [--direct-elements FILE] [--house-direct-elements FILE] [--house-private-dns-elements FILE] [--house-whatsapp-elements FILE] [--ssh-elements FILE] [--ntp-pass-elements FILE]")
		return 2
	}
	refuse := func(err error) int {
		if !render.IsSilent(err) {
			fmt.Fprintf(stderr, "pi-fortress: %v\n", err)
		}
		return 1
	}
	var e render.Elements
	for _, x := range []struct {
		path string
		dst  *string
	}{{*elems, &e.Blacklist}, {*dohElems, &e.DoH}, {*directElems, &e.DirectIP}, {*houseDirectElems, &e.HouseDirectIP}, {*privElems, &e.HousePrivateDNS}, {*waElems, &e.HouseWhatsApp}, {*sshElems, &e.SSHAllow}, {*ntpPassElems, &e.NTPPass}} {
		if x.path == "" {
			continue
		}
		data, err := os.ReadFile(x.path)
		if err != nil {
			return refuse(err)
		}
		*x.dst = strings.TrimRight(string(data), "\n")
	}
	c, err := render.Load(render.Options{
		Net: render.Net{
			AgentNet:        os.Getenv("AGENT_NET"),
			PiIP:            os.Getenv("PI_IP"),
			AgentIP:         os.Getenv("AGENT_IP"),
			DNSUpstream:     os.Getenv("DNS_UPSTREAM"),
			DoTAuthName:     os.Getenv("DOT_AUTH_NAME"),
			DoTIPs:          os.Getenv("DOT_IPS"),
			UntrustedUplink: os.Getenv("UNTRUSTED_UPLINK"),
			AgentDNS:        os.Getenv("AGENT_DNS"),
			FakeIPNet:       os.Getenv("FAKEIP_NET"),
			ConnLimits:      connLimitsFrom(os.Getenv),
			EnvSrc:          os.Getenv("NET_ENV_SRC"),
		},
		HouseEnv:    *houseEnv,
		SegmentsDir: *segDir,
		IntIF:       pick(*intIF, os.Getenv("INT_IF")),
		WanIF:       pick(*wanIF, os.Getenv("WAN_IF")),
		Live:        *live,
		Paranoid:    *paranoid,
		Stderr:      stderr,
	})
	if err != nil {
		return refuse(err)
	}
	if err := os.WriteFile(*outNFT, []byte(c.Ruleset(e)), 0644); err != nil {
		return refuse(err)
	}
	if err := os.WriteFile(*outEnv, []byte(c.EnvFile()+c.EgressEnv(e)), 0644); err != nil {
		return refuse(err)
	}
	return 0
}

// connLimitsFrom collects the connection-budget keys that apply.sh
// exports. An unset key is "", and render reads that as the default.
func connLimitsFrom(get func(string) string) map[string]string {
	m := make(map[string]string, len(render.ConnLimitKeys))
	for _, k := range render.ConnLimitKeys {
		m[k] = get(k)
	}
	return m
}

// pick is the flag when given, else the net.env name, else "" for
// detection.
func pick(flag, env string) string {
	if flag != "" {
		return flag
	}
	return env
}
