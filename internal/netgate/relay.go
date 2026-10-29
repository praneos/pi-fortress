package netgate

import (
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"pi-fortress/internal/nfq"
)

// Queue is the part of nfq.Queue that the relay uses. A test gives a fake.
type Queue interface {
	Recv() (nfq.Packet, error)
	Verdict(id uint32, verdict uint32, mark *uint32) error
	Close() error
}

const (
	// sniAge is how long netgate holds a packet for a verdict of pf dns.
	// The SNI check of pf dns holds a packet until the ClientHello is
	// complete (sniWait, 5 s) and the name has an answer (5 s). A packet
	// that is older is dropped. pf dns then refuses the flow, or its late
	// verdict finds nothing.
	sniAge = 15 * time.Second
	// sniHeld limits the packets that wait for a verdict. The kernel queue
	// holds 1024 (internal/nfq), so this is only a stop for a fault.
	sniHeld = 4096
	// sniSweep is how often the relay drops the packets older than sniAge.
	sniSweep = time.Second
)

// serveSNI makes c the relay of one SNI queue. netgate binds the queue
// only while pf dns is connected. When pf dns goes away, netgate closes
// the queue. The kernel then drops each packet that the queue held, and
// each packet that comes to it while nobody binds it (render queues with
// no bypass). This is the same as a pf dns that stops with the queue
// bound to it.
func (s *Server) serveSNI(c *net.UnixConn, first []byte) {
	num, err := decodeSNIHello(first)
	if err != nil {
		s.refuse("dns.sock: %v", err)
		return
	}
	answer := func(status byte, why string) bool {
		c.SetWriteDeadline(time.Now().Add(replyWait))
		_, err := c.Write(encodeReply(status, why))
		return err == nil
	}
	if !slices.Contains(s.cfg.Queues, num) {
		why := fmt.Sprintf("queue %d is not an SNI queue of dns.json", num)
		s.refuse("SNI refused: %s", why)
		answer(statusRefused, why)
		return
	}
	if !s.claimQueue(num) {
		why := fmt.Sprintf("queue %d has a client already", num)
		s.refuse("SNI refused: %s", why)
		answer(statusRefused, why)
		return
	}
	defer s.releaseQueue(num)
	q, err := s.cfg.OpenQueue(num)
	if err != nil {
		s.refuse("SNI queue %d: %v", num, err)
		answer(statusFailed, err.Error())
		return
	}
	r := &relay{q: q, c: c, num: num, now: s.cfg.Now, logf: s.cfg.Logf, age: s.cfg.sniAge, max: s.cfg.sniHeld, held: map[uint32]heldPacket{}}
	if !answer(statusOK, "") {
		q.Close()
		return
	}
	s.cfg.Logf("pf netgate: SNI queue %d: bound for pf dns", num)
	r.run(s.cfg.sniSweep)
	s.cfg.Logf("pf netgate: SNI queue %d: the relay ended; the queue is closed, and the kernel drops its packets", num)
}

func (s *Server) claimQueue(num uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queues[num] {
		return false
	}
	s.queues[num] = true
	return true
}

func (s *Server) releaseQueue(num uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.queues, num)
}

// heldPacket is a packet that waits for its verdict: the mark that the
// kernel gave, and when it came.
type heldPacket struct {
	mark uint32
	at   time.Time
}

// relay moves the packets of one queue to pf dns and the verdicts back.
// It reads no byte of a packet. It keeps the id and the mark of each
// packet that waits. A verdict for an id that it does not hold (unknown,
// late, or a second verdict) has no effect. A verdict can change only the
// SNI bits of the mark.
type relay struct {
	q    Queue
	c    *net.UnixConn
	num  uint16
	now  func() time.Time
	logf func(string, ...any)
	age  time.Duration
	max  int

	mu   sync.Mutex
	held map[uint32]heldPacket
	// log limits the lines of the ignored verdicts and the drops.
	log logLimit
}

// run returns when the queue or the connection fails. It closes both,
// so the other direction ends too.
func (r *relay) run(sweep time.Duration) {
	stop := sync.OnceFunc(func() {
		r.q.Close()
		r.c.Close()
	})
	var wg sync.WaitGroup
	wg.Go(func() {
		defer stop()
		r.fromQueue()
	})
	wg.Go(func() {
		defer stop()
		r.fromClient()
	})
	done, swept := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(swept)
		t := time.NewTicker(sweep)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				r.sweep()
			}
		}
	}()
	wg.Wait()
	close(done)
	<-swept
}

func (r *relay) fromQueue() {
	for {
		p, err := r.q.Recv()
		if err != nil {
			if !errors.Is(err, nfq.ErrClosed) {
				r.say("SNI queue %d: %v", r.num, err)
			}
			return
		}
		msg, err := encodePacket(p)
		if err != nil {
			r.say("SNI queue %d: %v; dropped", r.num, err)
			r.drop(p.ID)
			continue
		}
		if !r.hold(p) {
			r.say("SNI queue %d: packet %d dropped: %d packets wait for a verdict", r.num, p.ID, r.max)
			r.drop(p.ID)
			continue
		}
		r.c.SetWriteDeadline(time.Now().Add(replyWait))
		if _, err := r.c.Write(msg); err != nil {
			return
		}
	}
}

func (r *relay) fromClient() {
	buf := make([]byte, verdictLen+1)
	for {
		msg, err := readMsg(r.c, buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				r.say("SNI queue %d: %v; the relay is closed", r.num, err)
			}
			return
		}
		v, err := decodeVerdict(msg)
		if err != nil {
			r.say("SNI queue %d: %v; the relay is closed", r.num, err)
			return
		}
		r.mu.Lock()
		h, ok := r.held[v.id]
		delete(r.held, v.id)
		r.mu.Unlock()
		if !ok {
			r.say("SNI queue %d: verdict for packet %d, which waits for none; ignored", r.num, v.id)
			continue
		}
		if err := r.q.Verdict(v.id, v.verdict, v.mark(h.mark)); err != nil && !errors.Is(err, nfq.ErrClosed) {
			r.say("SNI queue %d: verdict for packet %d: %v", r.num, v.id, err)
		}
	}
}

func (r *relay) hold(p nfq.Packet) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.held) >= r.max {
		return false
	}
	r.held[p.ID] = heldPacket{mark: p.Mark, at: r.now()}
	return true
}

// sweep drops each packet that waited longer than r.age.
func (r *relay) sweep() {
	now := r.now()
	var old []uint32
	r.mu.Lock()
	for id, h := range r.held {
		if now.Sub(h.at) >= r.age {
			old = append(old, id)
			delete(r.held, id)
		}
	}
	r.mu.Unlock()
	for _, id := range old {
		r.drop(id)
	}
	if len(old) > 0 {
		r.say("SNI queue %d: %d packets waited %v with no verdict; dropped", r.num, len(old), r.age)
	}
}

func (r *relay) drop(id uint32) {
	if err := r.q.Verdict(id, nfq.Drop, nil); err != nil && !errors.Is(err, nfq.ErrClosed) {
		r.say("SNI queue %d: drop of packet %d: %v", r.num, id, err)
	}
}

func (r *relay) say(format string, args ...any) {
	r.log.say(r.now(), r.logf, format, args...)
}
