package render

import "strings"

// EnvFile is what apply.sh sources after render: all derived names that
// config.sh used to leave in the shell, as bash assignments. The values
// passed validation against fixed character classes. But they are
// single-quoted in all cases, so the file stays data if that changes.
func (c *Config) EnvFile() string {
	var b strings.Builder
	set := func(k, v string) { b.WriteString(k + "=" + shq(v) + "\n") }
	explicit := "0"
	if c.HouseDNSExplicit {
		explicit = "1"
	}
	set("INT_IF", c.IntIF)
	set("WAN_IF", c.WanIF)
	set("HOUSE_IF", c.HouseIF)
	set("HOUSE_NET", c.HouseNet)
	set("HOUSE_IP", c.HouseIP)
	set("HOUSE_DHCP_START", c.HouseDHCPStart)
	set("HOUSE_DHCP_END", c.HouseDHCPEnd)
	set("HOUSE_ADMIN_IP", c.HouseAdminIP)
	set("HOUSE_SSH_TO", c.HouseSSHTo)
	set("HOUSE_DNS_UPSTREAM", c.HouseDNSUpstream)
	set("HOUSE_DNS_EXPLICIT", explicit)
	set("HOUSE_PRIVATE_DNS", c.HousePrivateDNS)
	set("HOUSE_BLOCK_VPN", c.HouseBlockVPN)
	set("HOUSE_EGRESS", c.HouseEgress)
	set("HOUSE_ALLOW_WHATSAPP", c.HouseAllowWhatsApp)
	// The queue from which pf dns reads the pending 443 flows of the house.
	// Empty when the ruleset queues nothing (no house, or no direct-IP gate).
	sni := ""
	if c.HouseIF != "" && c.HouseBlockDirectIP != "off" {
		sni = SNIQueue
	}
	set("HOUSE_SNI_QUEUE", sni)
	set("WG_IF", c.WGIF)
	set("WG_BYPASS_MARK", c.WGBypassMark)
	set("DOT_AUTH_NAME", c.DoTAuthName)
	set("DOT_IPS", c.DoTIPs)
	set("DOT_ADDR", DoTAddr)
	set("HOUSE_DOT_AUTH_NAME", c.HouseDoTAuthName)
	set("HOUSE_DOT_IPS", c.HouseDoTIPs)
	set("HOUSE_DOT_ADDR", HouseDoTAddr)
	set("DNS_FORWARD", c.DNSForward)
	set("HOUSE_DNS_FORWARD", c.HouseDNSForward)
	// The validated pair, with defaults. Thus pf dns and the broker start
	// with the mode and pool that the ruleset was rendered for, not with
	// the text in net.env. Under fakeip, the broker resolves
	// through DNS_FORWARD above. That is the one resolver that the output
	// chain opens to it (ruleset.go, fakeIPGate).
	set("AGENT_DNS", c.AgentDNS)
	set("FAKEIP_NET", c.FakeIPNet)
	cols := map[string]func(Segment) string{
		"SEG_NAME": func(s Segment) string { return s.Name }, "SEG_IF": func(s Segment) string { return s.IF },
		"SEG_NET": func(s Segment) string { return s.Net }, "SEG_IP": func(s Segment) string { return s.IP },
		"SEG_ADMIN": func(s Segment) string { return s.Admin }, "SEG_SSH_TO": func(s Segment) string { return s.SSHTo },
		"SEG_DNS_TYPES": func(s Segment) string { return s.DNSTypes },
		// The checked allowlist path, empty when the segment is not
		// paranoid. Thus apply gives pf dns the same file that render refused or
		// accepted, and does not write the name a second time.
		"SEG_PARANOID": func(s Segment) string { return onOff(s.Paranoid) }, "SEG_ALLOW": func(s Segment) string { return s.AllowPath },
		// The checked INSPECT. Apply gives the engine a listener on the IP of
		// each inspected segment, and the broker its NET.
		"SEG_INSPECT": func(s Segment) string { return onOff(s.Inspect) },
		// The checked range. Thus apply writes each dnsmasq instance from
		// what render accepted, not from the text of the file.
		"SEG_DHCP": func(s Segment) string { return onOff(s.DHCP) }, "SEG_DHCP_START": func(s Segment) string { return s.DHCPStart },
		"SEG_DHCP_END": func(s Segment) string { return s.DHCPEnd },
		// The checked reservations, MAC,IP[,name] space separated: none
		// of the three can hold a space.
		"SEG_DHCP_HOSTS": func(s Segment) string {
			hs := make([]string, 0, len(s.Hosts))
			for _, h := range s.Hosts {
				hs = append(hs, h.String())
			}
			return strings.Join(hs, " ")
		},
	}
	for _, k := range []string{"SEG_NAME", "SEG_IF", "SEG_NET", "SEG_IP", "SEG_ADMIN", "SEG_SSH_TO", "SEG_DNS_TYPES", "SEG_PARANOID", "SEG_ALLOW", "SEG_INSPECT", "SEG_DHCP", "SEG_DHCP_START", "SEG_DHCP_END", "SEG_DHCP_HOSTS"} {
		vals := make([]string, 0, len(c.Segments))
		for _, s := range c.Segments {
			vals = append(vals, shq(cols[k](s)))
		}
		b.WriteString(k + "=(" + strings.Join(vals, " ") + ")\n")
	}
	parents := ""
	for _, p := range c.VLANParents {
		parents += p + " "
	}
	set("VLAN_PARENTS", parents)
	paranoid := "0"
	if c.Paranoid {
		paranoid = "1"
	}
	set("PARANOID", paranoid)
	return b.String()
}

func onOff(v string) string {
	if v == "on" {
		return "on"
	}
	return "off"
}

func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
