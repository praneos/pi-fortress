// Command ntpprobe is the NTP client of the lab tests (vm/itest ntp and
// ntp-fuzz). The lab clients have no NTP tool, so the test builds this and
// copies it to the client.
//
//	ntpprobe query [-timeout D] ADDR
//	    One NTPv4 client request to ADDR:123. It prints one line about the
//	    reply and exits 0, or exits 1 when no valid reply came.
//	ntpprobe fuzz -target IP [-rate N] [-duration D] [-seed N]
//	    Malformed and odd NTP packets to IP:123 at N packets each second. It
//	    prints the counts as JSON on stdout.
//
// Use it only against a lab gateway. The fuzz sends to one address, the
// one that -target names.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "query":
		os.Exit(query(os.Args[2:]))
	case "fuzz":
		os.Exit(fuzz(os.Args[2:]))
	}
	usage()
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ntpprobe query [-timeout D] ADDR | ntpprobe fuzz -target IP [-rate N] [-duration D] [-seed N]")
	os.Exit(2)
}

// ntpEpoch is the offset of the NTP era 0 from the Unix epoch, in seconds.
const ntpEpoch = 2208988800

func ntpTime(t time.Time) uint64 {
	s := uint64(t.Unix() + ntpEpoch)
	f := uint64(t.Nanosecond()) << 32 / 1e9
	return s<<32 | f
}

func fromNTP(v uint64) time.Time {
	s := int64(v>>32) - ntpEpoch
	ns := int64((v & 0xffffffff) * 1e9 >> 32)
	return time.Unix(s, ns)
}

// request is an NTPv4 client request (mode 3) with the transmit timestamp
// tx. The server copies tx into the origin timestamp of its reply.
func request(tx uint64) []byte {
	b := make([]byte, 48)
	b[0] = 0<<6 | 4<<3 | 3
	b[2] = 6 // poll 64 s
	b[3] = 0xec
	binary.BigEndian.PutUint64(b[40:], tx)
	return b
}

// Reply is the part of a server reply that the tests read.
type Reply struct {
	Leap, Version, Mode, Stratum int
	RefID                        string
	Size                         int
	Offset                       time.Duration
}

// parseReply checks that b is a server reply (mode 4) to the request with
// transmit timestamp tx.
func parseReply(b []byte, tx uint64, recv time.Time) (Reply, error) {
	if len(b) < 48 {
		return Reply{}, fmt.Errorf("short reply: %d bytes", len(b))
	}
	r := Reply{Leap: int(b[0] >> 6), Version: int(b[0] >> 3 & 7), Mode: int(b[0] & 7), Stratum: int(b[1]), Size: len(b)}
	r.RefID = netip.AddrFrom4([4]byte(b[12:16])).String()
	if r.Mode != 4 {
		return r, fmt.Errorf("mode %d, want 4", r.Mode)
	}
	if binary.BigEndian.Uint64(b[24:]) != tx {
		return r, errors.New("the origin timestamp is not the transmit timestamp of the request")
	}
	srvRx, srvTx := fromNTP(binary.BigEndian.Uint64(b[32:])), fromNTP(binary.BigEndian.Uint64(b[40:]))
	sent := fromNTP(tx)
	r.Offset = (srvRx.Sub(sent) + srvTx.Sub(recv)) / 2
	return r, nil
}

func query(args []string) int {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	timeout := fs.Duration("timeout", 3*time.Second, "time to wait for each reply")
	tries := fs.Int("tries", 2, "requests to send")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
	}
	addr, err := netip.ParseAddr(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer c.Close()
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 123))
	buf := make([]byte, 2048)
	for i := 0; i < *tries; i++ {
		tx := ntpTime(time.Now()) ^ rand.Uint64()&0xffff
		if _, err := c.WriteToUDP(request(tx), to); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		c.SetReadDeadline(time.Now().Add(*timeout))
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			r, err := parseReply(buf[:n], tx, time.Now())
			if err != nil {
				fmt.Fprintf(os.Stderr, "ignored a reply from %s: %v\n", from, err)
				continue
			}
			fmt.Printf("reply from=%s leap=%d version=%d mode=%d stratum=%d refid=%s size=%d offset=%s\n",
				from, r.Leap, r.Version, r.Mode, r.Stratum, r.RefID, r.Size, r.Offset.Round(time.Millisecond))
			return 0
		}
	}
	fmt.Println("no reply")
	return 1
}

// Stats are the counts of one fuzz run.
type Stats struct {
	Target   string           `json:"target"`
	Seconds  float64          `json:"seconds"`
	Sent     int64            `json:"sent"`
	SentByte int64            `json:"sent_bytes"`
	SendErr  int64            `json:"send_errors"`
	ByKind   map[string]int64 `json:"sent_by_kind"`
	// Replies is all datagrams that came back. Matched is the replies whose
	// origin timestamp names a request of this run, so the size of that
	// request is known.
	Replies    int64 `json:"replies"`
	ReplyBytes int64 `json:"reply_bytes"`
	Matched    int64 `json:"matched"`
	// MaxRatio is the largest reply size over its request size, of the
	// matched replies. MaxUnmatched is the largest reply that matched no
	// request. The server answers no request under 48 bytes.
	MaxRatio     float64 `json:"max_ratio"`
	MaxReply     int     `json:"max_reply"`
	MaxUnmatched int     `json:"max_unmatched"`
	// Mode67Replies is the replies on the sockets that sent only mode 6
	// (control) and mode 7 (private) packets.
	Mode67Replies int64 `json:"mode67_replies"`
	// KoD is the replies with stratum 0 (kiss-o'-death, e.g. RATE).
	KoD int64 `json:"kod"`
}

// sent is what the fuzz remembers of one request, by its transmit
// timestamp.
type sent struct{ size int }

type fuzzer struct {
	rng   *rand.Rand
	seq   uint64
	mu    sync.Mutex
	byTx  map[uint64]sent
	order []uint64
	stats Stats
}

// remember keeps the last 1<<16 requests, enough for the replies in flight.
func (f *fuzzer) remember(tx uint64, size int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.order) >= 1<<16 {
		delete(f.byTx, f.order[0])
		f.order = f.order[1:]
	}
	f.byTx[tx] = sent{size}
	f.order = append(f.order, tx)
}

func (f *fuzzer) lookup(tx uint64) (sent, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byTx[tx]
	return s, ok
}

func fuzz(args []string) int {
	fs := flag.NewFlagSet("fuzz", flag.ExitOnError)
	target := fs.String("target", "", "the gateway address (required)")
	rate := fs.Int("rate", 2000, "packets each second")
	dur := fs.Duration("duration", 5*time.Minute, "length of the run")
	seed := fs.Uint64("seed", uint64(time.Now().UnixNano()), "random seed")
	fs.Parse(args)
	addr, err := netip.ParseAddr(*target)
	if err != nil || !addr.Is4() {
		fmt.Fprintln(os.Stderr, "fuzz: -target must be an IPv4 address")
		return 2
	}
	if *rate < 1 || *rate > 5000 {
		fmt.Fprintln(os.Stderr, "fuzz: -rate must be 1 to 5000")
		return 2
	}
	f := &fuzzer{rng: rand.New(rand.NewPCG(*seed, *seed^0x9e3779b97f4a7c15)), byTx: map[uint64]sent{}}
	f.stats.Target = addr.String()
	f.stats.ByKind = map[string]int64{}
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 123))

	// Four sockets for the general packets, so that the server sees four
	// source ports. One socket only for mode 6 and mode 7: each datagram
	// that comes back on it is a reply to one of those.
	var general []*net.UDPConn
	for i := 0; i < 4; i++ {
		c, err := net.ListenUDP("udp4", nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		defer c.Close()
		general = append(general, c)
	}
	ctl, err := net.ListenUDP("udp4", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer ctl.Close()

	var wg sync.WaitGroup
	var stop atomic.Bool
	for _, c := range general {
		wg.Go(func() { f.read(c, false, &stop) })
	}
	wg.Go(func() { f.read(ctl, true, &stop) })

	start := time.Now()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	per := float64(*rate) / 100
	var owed float64
	for time.Since(start) < *dur {
		<-tick.C
		owed += per
		for ; owed >= 1; owed-- {
			kind, b := f.packet()
			c := general[int(f.seq)%len(general)]
			if len(b) > 0 && (b[0]&7 == 6 || b[0]&7 == 7) {
				c = ctl
			}
			f.seq++
			if _, err := c.WriteToUDP(b, to); err != nil {
				atomic.AddInt64(&f.stats.SendErr, 1)
				continue
			}
			f.mu.Lock()
			f.stats.Sent++
			f.stats.SentByte += int64(len(b))
			f.stats.ByKind[kind]++
			f.mu.Unlock()
		}
	}
	// The last replies.
	time.Sleep(2 * time.Second)
	stop.Store(true)
	for _, c := range general {
		c.SetReadDeadline(time.Now())
	}
	ctl.SetReadDeadline(time.Now())
	wg.Wait()
	f.stats.Seconds = time.Since(start).Seconds()
	out, _ := json.Marshal(f.stats)
	fmt.Println(string(out))
	return 0
}

func (f *fuzzer) read(c *net.UDPConn, ctl bool, stop *atomic.Bool) {
	buf := make([]byte, 65536)
	for {
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if stop.Load() {
				return
			}
			continue
		}
		b := buf[:n]
		f.mu.Lock()
		f.stats.Replies++
		f.stats.ReplyBytes += int64(n)
		f.stats.MaxReply = max(f.stats.MaxReply, n)
		if ctl {
			f.stats.Mode67Replies++
		}
		if n >= 2 && b[1] == 0 {
			f.stats.KoD++
		}
		f.mu.Unlock()
		if n < 32 {
			f.unmatched(n)
			continue
		}
		s, ok := f.lookup(binary.BigEndian.Uint64(b[24:]))
		if !ok {
			f.unmatched(n)
			continue
		}
		f.mu.Lock()
		f.stats.Matched++
		f.stats.MaxRatio = max(f.stats.MaxRatio, float64(n)/float64(s.size))
		f.mu.Unlock()
	}
}

func (f *fuzzer) unmatched(n int) {
	f.mu.Lock()
	f.stats.MaxUnmatched = max(f.stats.MaxUnmatched, n)
	f.mu.Unlock()
}

// packet is the next fuzz packet and the name of its kind. Each packet of
// 48 bytes or more has a unique transmit timestamp, which the fuzz
// remembers. Thus a reply can be matched to its request.
func (f *fuzzer) packet() (string, []byte) {
	r := f.rng
	// The seconds of now, and the sequence number as the fraction.
	tx := ntpTime(time.Now())&^0xffffffff | f.seq&0xffffffff
	var kind string
	var b []byte
	switch k := r.IntN(100); {
	case k < 12:
		kind, b = "random", f.bytes(r.IntN(1501))
	case k < 22:
		kind, b = "header", f.header()
	case k < 30:
		kind, b = "truncated", request(tx)[:r.IntN(48)]
	case k < 45:
		kind, b = "extension", f.extensions(request(tx), false)
	case k < 55:
		kind, b = "nts", f.extensions(request(tx), true)
	case k < 62:
		kind, b = "oversized", f.oversized(request(tx))
	case k < 80:
		kind, b = "mutated", f.mutate(request(tx))
	case k < 85:
		kind, b = "mac", f.mac(request(tx))
	case k < 93:
		kind, b = "mode6", f.mode6()
	default:
		kind, b = "mode7", f.mode7()
	}
	if len(b) > 1500 {
		b = b[:1500]
	}
	if len(b) >= 48 {
		// The mutation may have changed the timestamp. Remember the one that
		// is in the packet.
		f.remember(binary.BigEndian.Uint64(b[40:]), len(b))
	}
	return kind, b
}

func (f *fuzzer) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(f.rng.Uint32())
	}
	return b
}

// header is 48 bytes with each version and each mode, random fields, and a
// transmit timestamp that the fuzz can match.
func (f *fuzzer) header() []byte {
	b := f.bytes(48)
	b[0] = byte(f.rng.IntN(4))<<6 | byte(f.rng.IntN(8))<<3 | byte(f.rng.IntN(8))
	return b
}

// extensions adds extension fields to a request. Their type, length and
// body are random or NTS-shaped (the NTS types of RFC 8915: unique
// identifier 0x0104, cookie 0x0204, cookie placeholder 0x0304,
// authenticator 0x0404) with garbage in them. The length field is
// sometimes wrong: 0, under 16, odd, or past the end of the packet.
func (f *fuzzer) extensions(b []byte, nts bool) []byte {
	r := f.rng
	types := []uint16{0x0104, 0x0204, 0x0304, 0x0404}
	for n := 1 + r.IntN(6); n > 0 && len(b) < 1400; n-- {
		typ := uint16(r.Uint32())
		if nts || r.IntN(2) == 0 {
			typ = types[r.IntN(len(types))]
		}
		body := r.IntN(300)
		if typ == 0x0104 {
			body = 32
		}
		length := 4 + body
		if r.IntN(4) == 0 {
			length += (4 - length%4) % 4
		}
		switch r.IntN(8) {
		case 0:
			length = 0
		case 1:
			length = r.IntN(16)
		case 2:
			length = 0xffff
		case 3:
			length = 4 + body + 1 + r.IntN(200)
		}
		ef := make([]byte, 4, 4+body)
		binary.BigEndian.PutUint16(ef, typ)
		binary.BigEndian.PutUint16(ef[2:], uint16(length))
		ef = append(ef, f.bytes(body)...)
		if typ == 0x0404 && body >= 4 {
			// Nonce and ciphertext lengths, most of the time impossible.
			binary.BigEndian.PutUint16(ef[4:], uint16(r.Uint32()))
			binary.BigEndian.PutUint16(ef[6:], uint16(r.Uint32()))
		}
		b = append(b, ef...)
	}
	return b
}

// oversized is a request with one extension field that claims a large
// length, padded to a large size, or a request padded with zeros to the
// largest datagram that the fuzz sends.
func (f *fuzzer) oversized(b []byte) []byte {
	switch f.rng.IntN(3) {
	case 0:
		ef := []byte{0x02, 0x04, 0xff, 0xfc}
		b = append(b, ef...)
		return append(b, f.bytes(1500-len(b))...)
	case 1:
		return append(b, make([]byte, 1500-len(b))...)
	}
	ef := []byte{0x01, 0x04, 0x05, 0xc8} // 1480: the full rest of the packet
	b = append(b, ef...)
	return append(b, f.bytes(1476)...)
}

// mutate changes a valid request: bit flips, random bytes, a cut, a
// repeat, or garbage at the end.
func (f *fuzzer) mutate(b []byte) []byte {
	r := f.rng
	for n := 1 + r.IntN(4); n > 0; n-- {
		switch r.IntN(6) {
		case 0:
			i := r.IntN(len(b))
			b[i] ^= 1 << r.IntN(8)
		case 1:
			b[r.IntN(len(b))] = byte(r.Uint32())
		case 2:
			if len(b) > 1 {
				b = b[:1+r.IntN(len(b)-1)]
			}
		case 3:
			b = append(b, b...)
		case 4:
			b = append(b, f.bytes(r.IntN(200))...)
		case 5:
			b[0] = b[0]&0xc0 | byte(r.IntN(8))<<3 | byte(r.IntN(8))
		}
	}
	return b
}

// mac is a request with a symmetric-key MAC tail: a key ID and 16 or 20
// bytes of digest (MD5, SHA1), or a crypto-NAK (the key ID alone), with
// random keys that the server does not have.
func (f *fuzzer) mac(b []byte) []byte {
	switch f.rng.IntN(4) {
	case 0:
		return append(b, f.bytes(4)...)
	case 1:
		return append(b, f.bytes(20)...)
	case 2:
		return append(b, f.bytes(24)...)
	}
	return append(b, f.bytes(4+f.rng.IntN(64))...)
}

// mode6 is an NTP control message (ntpq): opcodes 0 to 31, read status and
// read variables most of the time, with random data. The request bit is
// clear. A server that answers it can amplify (CVE-2013-5211 class).
func (f *fuzzer) mode6() []byte {
	r := f.rng
	data := r.IntN(469)
	b := make([]byte, 12, 12+data+4)
	b[0] = byte(r.IntN(4))<<6 | byte(1+r.IntN(4))<<3 | 6
	op := byte(r.IntN(32))
	if r.IntN(2) == 0 {
		op = 1 + byte(r.IntN(2))
	}
	b[1] = op
	binary.BigEndian.PutUint16(b[2:], uint16(r.Uint32()))
	binary.BigEndian.PutUint16(b[6:], uint16(r.IntN(4)))
	binary.BigEndian.PutUint16(b[10:], uint16(data))
	b = append(b, f.bytes(data)...)
	return append(b, f.bytes(r.IntN(2)*20)...)
}

// mode7 is an NTP private message (ntpdc): implementations 0, 2, 3 and
// request codes such as MON_GETLIST_1 (42, the monlist amplifier).
func (f *fuzzer) mode7() []byte {
	r := f.rng
	b := make([]byte, 8, 8+40+r.IntN(500))
	b[0] = byte(r.IntN(2))<<7 | byte(r.IntN(2))<<6 | byte(1+r.IntN(4))<<3 | 7
	b[1] = byte(r.Uint32())
	b[2] = []byte{0, 2, 3}[r.IntN(3)]
	b[3] = byte(r.IntN(46))
	if r.IntN(2) == 0 {
		b[3] = 42
	}
	binary.BigEndian.PutUint16(b[4:], uint16(r.IntN(2))<<12|uint16(r.IntN(4)))
	binary.BigEndian.PutUint16(b[6:], uint16(r.IntN(500)))
	return append(b, f.bytes(cap(b)-8)...)
}
