package dnsd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
)

// The flag set carries one segment: -iface, -ip, -upstream and the other
// flags name the policy of a single interface. A systemd unit that reads
// one environment variable per flag cannot express a second. The house
// runs on this daemon next to the agent. Each segments.d file adds one
// more. Thus the configuration must be a list that the caller can extend,
// without a new daemon flag for each segment.
//
// The format is JSON, not a repeatable grouped flag, because the sinkhole
// of a segment is itself a list. A grouped flag would need one separator
// inside another. The unit would also still need a variable per segment.
// A file is one flag and one path. -check validates the same bytes that
// the daemon runs.

// wireConfig is the shape of the file. It is separate from Config on
// purpose. Config has an atomically published list and an upstream leg,
// and an operator writes neither. This code parses durations and addresses
// here, so that a bad one names its field and its segment.
type wireConfig struct {
	Listen    int     `json:"listen"`
	NFTTable  string  `json:"nft_table"`
	CacheSize int     `json:"cache_size"`
	MaxTTL    string  `json:"max_ttl"`
	LogRate   float64 `json:"log_rate"`
	LogBurst  int     `json:"log_burst"`
	// LogFormat exists only so that the parser can refuse it. The log is one
	// row per transaction. "text" was the two-line format of dnsmasq, and it
	// is retired. A stale value must be an error, not an ignored field.
	// Otherwise an operator who wrote it to get the old format back would get
	// the new one, with no message.
	LogFormat string        `json:"log_format"`
	Segments  []wireSegment `json:"segments"`
}

type wireSegment struct {
	Name      string   `json:"name"`
	Iface     string   `json:"iface"`
	IP        string   `json:"ip"`
	Upstream  string   `json:"upstream"`
	DoTName   string   `json:"dot_name"`
	DoTIPs    []string `json:"dot_ips"`
	DoTIface  string   `json:"dot_iface"`
	SNIQueue  uint16   `json:"sni_queue"`
	SNIECH    string   `json:"sni_ech_ips"`
	SNIOpaque string   `json:"sni_opaque_ips"`
	Sinkhole  []string `json:"sinkhole"`
	NFTSet    string   `json:"nft_set"`
	Log       string   `json:"log"`
	Paranoid  bool     `json:"paranoid"`
	Allow     string   `json:"allow"`
	Core      string   `json:"core_hosts"`
	LabEcho   bool     `json:"lab_echo"`
	KeyRules  string   `json:"key_rules"`
	AOnly     bool     `json:"address_only"`
	TypesOK   string   `json:"dns_types_allow"`
	Types     string   `json:"dns_types"`
	FakeNet   string   `json:"fakeip_net"`
	FakeJrnl  string   `json:"fakeip_journal"`
}

// ParseConfig reads the segment list. It sets no value that New would not
// set anyway. Its job is to change text into the typed Config. It also
// refuses text that would otherwise get to New as a zero value, because
// there a zero means "not configured", not "written wrong".
func ParseConfig(r io.Reader) (Config, error) {
	dec := json.NewDecoder(r)
	// An unknown key is a typo in a file that nobody reads back. To accept it
	// silently gives a segment a default that nobody chose. For example,
	// "nft-set" for "nft_set" would feed the wrong set.
	dec.DisallowUnknownFields()
	var w wireConfig
	if err := dec.Decode(&w); err != nil {
		return Config{}, fmt.Errorf("dns config: %w", err)
	}
	if len(w.Segments) == 0 {
		return Config{}, fmt.Errorf("dns config: no segments")
	}
	cfg := Config{
		NFTTable:  w.NFTTable,
		Listen:    w.Listen,
		CacheSize: w.CacheSize,
		LogRate:   w.LogRate,
		LogBurst:  w.LogBurst,
	}
	if w.LogFormat != "" && w.LogFormat != "jsonl" {
		return Config{}, fmt.Errorf("dns config: log_format %q is retired; the log is one row per transaction", w.LogFormat)
	}
	if w.MaxTTL != "" {
		d, err := time.ParseDuration(w.MaxTTL)
		if err != nil {
			return Config{}, fmt.Errorf("dns config: max_ttl %q: %w", w.MaxTTL, err)
		}
		cfg.MaxTTL = d
	}
	for i, s := range w.Segments {
		// The name of the segment if it has one. If not, its index. Thus the agent
		// segment (name "") still shows which entry is wrong.
		where := fmt.Sprintf("segment %d", i)
		if s.Name != "" {
			where = fmt.Sprintf("segment %q", s.Name)
		}
		addr, err := netip.ParseAddr(s.IP)
		if err != nil {
			return Config{}, fmt.Errorf("dns config: %s: ip %q: %w", where, s.IP, err)
		}
		var dots []netip.Addr
		for _, raw := range s.DoTIPs {
			// Also accept space-separated values. net.env writes DOT_IPS that way. A
			// renderer that copies the value through should not have to split it.
			for _, f := range strings.Fields(raw) {
				a, err := netip.ParseAddr(f)
				if err != nil {
					return Config{}, fmt.Errorf("dns config: %s: dot_ips %q: %w", where, f, err)
				}
				dots = append(dots, a)
			}
		}
		// Parse as written, not masked. The ruleset gates the prefix that apply
		// rendered. A pool that silently became a different network here would
		// give addresses that the gate drops.
		var fake netip.Prefix
		if s.FakeNet != "" {
			fake, err = netip.ParsePrefix(s.FakeNet)
			if err != nil {
				return Config{}, fmt.Errorf("dns config: %s: fakeip_net %q: %w", where, s.FakeNet, err)
			}
			if fake != fake.Masked() {
				return Config{}, fmt.Errorf("dns config: %s: fakeip_net %q has host bits set; write %s", where, s.FakeNet, fake.Masked())
			}
		}
		var extra []uint16
		for _, tok := range strings.Fields(s.Types) {
			t, ok := parseQType(tok)
			if !ok {
				return Config{}, fmt.Errorf("dns config: %s: dns_types %q is not a DNS type", where, tok)
			}
			extra = append(extra, t)
		}
		var files []string
		for _, p := range s.Sinkhole {
			if p = strings.TrimSpace(p); p != "" {
				files = append(files, p)
			}
		}
		cfg.Segments = append(cfg.Segments, Segment{
			Name:           s.Name,
			Iface:          s.Iface,
			IP:             addr,
			Upstream:       s.Upstream,
			DoTName:        s.DoTName,
			DoTIPs:         dots,
			DoTIface:       s.DoTIface,
			SNIQueue:       s.SNIQueue,
			SNIECHFile:     s.SNIECH,
			SNIOpaqueFile:  s.SNIOpaque,
			SinkholeFiles:  files,
			NFTSet:         s.NFTSet,
			LogPath:        s.Log,
			Paranoid:       s.Paranoid,
			AllowPath:      s.Allow,
			CorePath:       s.Core,
			LabEcho:        s.LabEcho,
			KeyRulesPath:   s.KeyRules,
			AddressOnly:    s.AOnly,
			TypesAllowPath: s.TypesOK,
			ExtraTypes:     extra,
			FakeIPNet:      fake,
			FakeIPJournal:  s.FakeJrnl,
		})
	}
	return cfg, nil
}
