// Package tui is the pf tui screen program: a keyboard-only front end
// over internal/admin for the seat and for ssh, stdlib only.
package tui

import (
	"io"
	"time"
	"unicode/utf8"
)

type KeyKind int

const (
	KeyRune KeyKind = iota
	KeyEnter
	KeyEsc
	KeyBackspace
	KeyTab
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyPgUp
	KeyPgDn
	KeyHome
	KeyEnd
	KeyF5
	KeyCtrlC
	KeyCtrlR
	KeyResize
)

type Key struct {
	Kind KeyKind
	Rune rune
}

// Terminal is what the app needs from a tty. ReadKey blocks. It returns
// KeyResize when the window changed, and io.EOF when the input is gone.
type Terminal interface {
	Size() (w, h int)
	ReadKey() (Key, error)
	Write(p []byte) error
	EnterRaw() error
	Restore()
}

const escWait = 40 * time.Millisecond

var escSeqs = map[string]KeyKind{
	"[A": KeyUp, "[B": KeyDown, "[C": KeyRight, "[D": KeyLeft,
	"OA": KeyUp, "OB": KeyDown, "OC": KeyRight, "OD": KeyLeft,
	"[H": KeyHome, "[F": KeyEnd, "OH": KeyHome, "OF": KeyEnd,
	"[1~": KeyHome, "[4~": KeyEnd, "[7~": KeyHome, "[8~": KeyEnd,
	"[5~": KeyPgUp, "[6~": KeyPgDn, "[15~": KeyF5, "[[E": KeyF5,
}

// parseKey changes one byte, plus all bytes that follow an escape within
// escWait, into a Key. next returns the following byte, or false on
// timeout. It is the only place where the parser waits. unread, when not
// nil, gives a byte back to be the next key. Before, when Esc and a key
// arrived together, the second key was lost in the escape wait (an ssh
// session bunches keystrokes on a slow link). Thus Esc then q or a digit
// did only the Esc.
func parseKey(b byte, next func(time.Duration) (byte, bool), unread func(byte)) Key {
	switch b {
	case '\r', '\n':
		return Key{Kind: KeyEnter}
	case 0x7f, 0x08:
		return Key{Kind: KeyBackspace}
	case '\t':
		return Key{Kind: KeyTab}
	case 0x03:
		return Key{Kind: KeyCtrlC}
	case 0x12:
		return Key{Kind: KeyCtrlR}
	case 0x1b:
		seq := ""
		for len(seq) < 6 {
			c, ok := next(escWait)
			if !ok {
				break
			}
			seq += string(c)
			if k, ok := escSeqs[seq]; ok {
				return Key{Kind: k}
			}
			if len(seq) == 1 && c != '[' && c != 'O' {
				// Not a sequence: the Esc is alone, and c is the next
				// key, not part of it. The TUI binds no Alt keys.
				if unread != nil {
					unread(c)
				}
				break
			}
			if len(seq) > 1 && (c == '~' || (c >= 'A' && c <= 'Z')) {
				break
			}
		}
		return Key{Kind: KeyEsc}
	}
	if b < 0x20 {
		return Key{Kind: KeyRune}
	}
	if b < utf8.RuneSelf {
		return Key{Kind: KeyRune, Rune: rune(b)}
	}
	// A terminal sends a character as its UTF-8 bytes. Before, the code
	// widened the lead byte to a rune and encoded it again. This changed
	// each accented letter into two Latin-1 letters. Thus an operator with
	// a passphrase that is not plain ASCII could never unlock the store
	// from the seat.
	return Key{Kind: KeyRune, Rune: utf8Rune(b, next)}
}

// utf8Rune assembles one character from its lead byte and the continuation
// bytes that it announces. A sequence that the terminal truncates or
// malforms becomes U+FFFD, not a byte that looks like a rune.
func utf8Rune(lead byte, next func(time.Duration) (byte, bool)) rune {
	n := 0
	switch {
	case lead&0xe0 == 0xc0:
		n = 1
	case lead&0xf0 == 0xe0:
		n = 2
	case lead&0xf8 == 0xf0:
		n = 3
	default:
		return utf8.RuneError
	}
	buf := make([]byte, 1, 4)
	buf[0] = lead
	for range n {
		c, ok := next(escWait)
		if !ok || c&0xc0 != 0x80 {
			return utf8.RuneError
		}
		buf = append(buf, c)
	}
	r, size := utf8.DecodeRune(buf)
	if size != len(buf) {
		return utf8.RuneError
	}
	return r
}

// byteSource feeds parseKey from a reader on its own goroutine. Thus the
// escape timeout and a resize signal can both interrupt a read.
//
// The code can tell its goroutine to stop, but cannot make it return from
// a read in progress. read(2) on a tty blocks until a byte arrives. To
// close the tty under it is not the job of this type, because the fd is
// the stdin of the process. Thus after a stop, the goroutine ends at the
// next byte or the next read error. For a seat, that is when the operator
// next touches the keyboard or the session closes. One goroutine, one time
// per process, waits on a read that nobody waits for.
type byteSource struct {
	ch  chan byte
	err chan error
	// back holds the bytes that parseKey gave back (unread). They come out of
	// next and pending before newer bytes. Only the goroutine that reads keys
	// touches it.
	back []byte
}

func (s *byteSource) unread(b byte) { s.back = append(s.back, b) }

// pending returns a byte that was given back, if there is one, for ReadKey
// to parse before it waits on the tty.
func (s *byteSource) pending() (byte, bool) {
	if len(s.back) == 0 {
		return 0, false
	}
	b := s.back[0]
	s.back = s.back[1:]
	return b, true
}

// newByteSource pumps r until stop is closed or r fails. stop stops the
// pump. Before, the sends below were unconditional. Thus when the app
// stopped its key reads, the pump blocked on a full channel for the life
// of the process. stop cannot interrupt the read itself (refer to the
// caveat on the type), but it does end the goroutine at the next byte.
func newByteSource(r io.Reader, stop <-chan struct{}) *byteSource {
	s := &byteSource{ch: make(chan byte, 64), err: make(chan error, 1)}
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := r.Read(buf)
			for _, b := range buf[:n] {
				select {
				case s.ch <- b:
				case <-stop:
					return
				}
			}
			if err != nil {
				select {
				case s.err <- err:
				case <-stop:
				}
				return
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	return s
}

func (s *byteSource) next(d time.Duration) (byte, bool) {
	if b, ok := s.pending(); ok {
		return b, true
	}
	select {
	case b := <-s.ch:
		return b, true
	case <-time.After(d):
		return 0, false
	}
}
