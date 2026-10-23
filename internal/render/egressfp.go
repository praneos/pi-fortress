package render

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// EgressEnv is the part of apply.env that tells apply when the egress
// policy of a segment changed. HOUSE_EGRESS_FP is the fingerprint of the
// house policy, empty when there is no house. SEG_EGRESS_FP has one
// fingerprint for each plain segment, in the order of SEG_NAME. apply.sh
// keeps the last values and ends the open flows of each segment whose
// value changed. The ruleset accepts an established flow without a new
// policy check, so without this a flow keeps the old permission.
//
// The agent gets no fingerprint: its raw chain checks each packet again.
func (c *Config) EgressEnv(e Elements) string {
	house := ""
	if c.HouseIF != "" {
		house = c.houseEgressFP()
	}
	fps := make([]string, 0, len(c.Segments))
	for _, s := range c.Segments {
		fps = append(fps, shq(segEgressFP(s, e)))
	}
	return "HOUSE_EGRESS_FP=" + shq(house) + "\nSEG_EGRESS_FP=(" + strings.Join(fps, " ") + ")\n"
}

// houseEgressFP covers HOUSE_EGRESS, the HOUSE_ALLOW_* switches,
// HOUSE_ALLOW_PORTS, the HOUSE_BLOCK_* switches and HOUSE_PRIVATE_DNS. An
// unset key counts as its default. Thus a line that only writes the
// default does not cut flows.
func (c *Config) houseEgressFP() string {
	return egressFP("house",
		"egress="+orDefault(c.HouseEgress, "strict"),
		"block_direct_ip="+orDefault(c.HouseBlockDirectIP, "on"),
		"block_http="+orDefault(c.HouseBlockHTTP, "off"),
		"block_vpn="+orDefault(c.HouseBlockVPN, "on"),
		"private_dns="+orDefault(c.HousePrivateDNS, "off"),
		"wifi_calling="+orDefault(c.HouseAllowWiFiCalling, "off"),
		"call_udp="+orDefault(c.HouseAllowCallUDP, "off"),
		"whatsapp="+orDefault(c.HouseAllowWhatsApp, "on"),
		"tcp="+c.HouseAllowTCP,
		"udp="+c.HouseAllowUDP)
}

// segEgressFP covers EGRESS, ALLOW_PORTS and BLOCK_DIRECT_IP of a plain
// segment, and the ssh_allow.ips elements, which open SSH from each plain
// segment.
func segEgressFP(s Segment, e Elements) string {
	return egressFP("segment",
		"egress="+orDefault(s.Egress, "strict"),
		"block_direct_ip="+orDefault(s.BlockDirectIP, "on"),
		"tcp="+s.AllowTCP,
		"udp="+s.AllowUDP,
		"ssh_allow="+e.SSHAllow)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// egressFP is a short hash of the fields, one per line, after a version
// line. A different set of fields gets a different version.
func egressFP(kind string, fields ...string) string {
	sum := sha256.Sum256([]byte("egress-v1 " + kind + "\n" + strings.Join(fields, "\n") + "\n"))
	return hex.EncodeToString(sum[:8])
}
