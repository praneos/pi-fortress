// Package netgate is pf netgate: the one daemon that holds CAP_NET_ADMIN
// for pf dns and pf observe. It does a small set of fixed jobs for them,
// and nothing else:
//
//   - GATE: add public IPv4 addresses to a resolver gate set, or restart
//     their timeout, for the agent resolver (pf dns).
//   - SNI: own the NFQUEUE of the house SNI check. netgate relays each
//     queued packet to pf dns, and pf dns gives the verdict back.
//   - CT: run `conntrack -L -o extended` for pf observe.
//
// pf dns and pf observe parse bytes from the network. Before netgate,
// both held CAP_NET_ADMIN. With that capability, code that runs in either
// process can change any part of the network setup of the box: the
// ruleset, routes, links and bridges. netgate takes only fixed binary
// messages on two unix sockets, one for each client. Only the group of
// that client can open its socket, and netgate also checks the uid and
// gid of the peer. It parses no packet. Of a queued packet, it reads only
// the netlink attributes (id, mark, payload) and copies the payload to
// pf dns.
//
// Each client fails closed when netgate is down. pf dns answers SERVFAIL
// when a GATE fails. The kernel drops the queued packets when no socket
// binds the queue. observe gets no conntrack rows.
//
// It uses only the standard library and the small packages nfq and
// gateset (imports_test.go).
package netgate

import (
	"encoding/json"
	"fmt"
	"io"
	"os/user"
	"regexp"
	"slices"
	"strconv"

	"pi-fortress/internal/gateset"
)

// Paths. The directory is the RuntimeDirectory of the unit. It is not
// /run/pi-fortress, which only root and pf-fence can enter.
const (
	Dir       = "/run/pi-fortress-netgate"
	DNSSocket = Dir + "/dns.sock"
	CTSocket  = Dir + "/ct.sock"
)

// Peer is the uid and gid that a client must have. The gid is the
// primary group of the process (SO_PEERCRED), not a supplementary group.
type Peer struct {
	UID, GID uint32
}

// allows reports if a process with uid and gid is this peer.
func (p Peer) allows(uid, gid uint32) bool { return uid == p.UID && gid == p.GID }

// DNSConfig is what netgate reads from the dns.json of pf dns: the nft
// table, the gate sets and the SNI queues. pf dns reads the same file.
// Thus the two agree on which sets and which queues exist.
type DNSConfig struct {
	Table  string
	Sets   []string
	Queues []uint16
}

// tableName is the form of nft_table: a family and a name. The value goes
// into the text of an nft command, so it must be exactly this.
var tableName = regexp.MustCompile(`^(ip|inet) [A-Za-z0-9_]+$`)

// maxSetName is the size of the set name field of a GATE request.
const maxSetName = 32

// maxConfig limits the read of dns.json. The real file is a few KiB.
const maxConfig = 1 << 20

// ParseDNSConfig reads dns.json. It reads only the keys that it needs
// and ignores the others: pf dns -check is the full check of the file.
// A set that is not a resolver set (gateset.IsResolverSet), or that does
// not fit a GATE request, is skipped and reported in skipped. A GATE for
// that set is then refused, and its segment answers SERVFAIL.
func ParseDNSConfig(r io.Reader) (cfg DNSConfig, skipped []string, err error) {
	var w struct {
		Table    string `json:"nft_table"`
		Segments []struct {
			Set   string `json:"nft_set"`
			Queue uint16 `json:"sni_queue"`
		} `json:"segments"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxConfig)).Decode(&w); err != nil {
		return DNSConfig{}, nil, fmt.Errorf("dns config: %w", err)
	}
	if !tableName.MatchString(w.Table) {
		return DNSConfig{}, nil, fmt.Errorf("dns config: nft_table %q is not \"<family> <name>\"", w.Table)
	}
	cfg.Table = w.Table
	for _, s := range w.Segments {
		switch {
		case s.Set == "":
		case !gateset.IsResolverSet(s.Set) || len(s.Set) > maxSetName:
			skipped = append(skipped, s.Set)
		case !slices.Contains(cfg.Sets, s.Set):
			cfg.Sets = append(cfg.Sets, s.Set)
		}
		if s.Queue != 0 && !slices.Contains(cfg.Queues, s.Queue) {
			cfg.Queues = append(cfg.Queues, s.Queue)
		}
	}
	return cfg, skipped, nil
}

// The accounts of the client of dns.sock, as apply makes them. The agent
// resolver runs as DNSUser with DNSGroup as its primary group. The DoT
// stubs also run as DNSUser, but with a different group. Thus the gid
// tells the two apart. DNSGroup is also the group of dns.sock.
const (
	DNSUser  = "pf-dns"
	DNSGroup = "pf-dnsgate"
)

// LookupPeer gives the uid of account and the gid of group.
func LookupPeer(account, group string) (Peer, error) {
	u, err := user.Lookup(account)
	if err != nil {
		return Peer{}, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return Peer{}, fmt.Errorf("account %s: uid %q", account, u.Uid)
	}
	gid, err := LookupGroup(group)
	if err != nil {
		return Peer{}, err
	}
	return Peer{UID: uint32(uid), GID: uint32(gid)}, nil
}

// LookupGroup gives the gid of group.
func LookupGroup(group string) (int, error) {
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("group %s: gid %q", group, g.Gid)
	}
	return int(gid), nil
}
