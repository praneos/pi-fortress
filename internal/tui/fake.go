package tui

import (
	"io"
	"strings"
	"sync"
	"sync/atomic"
)

// Fake is an in-memory Terminal. Keys come from a script, and it keeps
// frames for assertions. ReadKey returns io.EOF when the script has no more
// keys. This ends the app loop.
type Fake struct {
	mu     sync.Mutex
	W, H   int
	keys   []Key
	Frames []string
	Raw    bool
	// Hold makes ReadKey block, and not return io.EOF, after the script is
	// consumed. It is for tests that end the loop a different way.
	Hold bool
	// Restore closes wake, and EnterRaw makes a new one after that, as the
	// real terminal does. A held ReadKey is a worker that waits in a
	// terminal read. The app must be able to get it back before the app
	// returns.
	wake chan struct{}
	// inRead counts the goroutines inside ReadKey. A test uses it to see a
	// leaked goroutine.
	inRead atomic.Int64
}

func NewFake(w, h int) *Fake { return &Fake{W: w, H: h, wake: make(chan struct{})} }

// InRead is the number of goroutines that are blocked in ReadKey now. A
// TUI that has returned must leave none.
func (f *Fake) InRead() int { return int(f.inRead.Load()) }

// Type queues plain text. Each rune is one key. Enter, Esc and the
// navigation keys go through Press.
func (f *Fake) Type(s string) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range s {
		f.keys = append(f.keys, Key{Kind: KeyRune, Rune: r})
	}
	return f
}

// Paste queues s as the real terminal reads it in one read: each rune is a
// key, and each line end at the end of s is an Enter with Paste set. s
// has no line end before its text ends.
func (f *Fake) Paste(s string) *Fake {
	from := pasteFrom([]byte(s))
	f.Type(s[:from])
	f.mu.Lock()
	defer f.mu.Unlock()
	for range s[from:] {
		f.keys = append(f.keys, Key{Kind: KeyEnter, Paste: true})
	}
	return f
}

func (f *Fake) Press(kinds ...KeyKind) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range kinds {
		f.keys = append(f.keys, Key{Kind: k})
	}
	return f
}

func (f *Fake) Resize(w, h int) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.W, f.H = w, h
	f.keys = append(f.keys, Key{Kind: KeyResize})
	return f
}

func (f *Fake) Size() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.W, f.H
}

func (f *Fake) ReadKey() (Key, error) {
	f.inRead.Add(1)
	defer f.inRead.Add(-1)
	f.mu.Lock()
	if len(f.keys) == 0 {
		hold, wake := f.Hold, f.wake
		f.mu.Unlock()
		if !hold {
			return Key{}, io.EOF
		}
		// Hold blocks until Restore, never forever. A read that nothing can end
		// is a leak. The test would hang on it, and not report it.
		<-wake
		return Key{}, io.EOF
	}
	k := f.keys[0]
	f.keys = f.keys[1:]
	f.mu.Unlock()
	return k, nil
}

func (f *Fake) Write(p []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Frames = append(f.Frames, string(p))
	return nil
}

func (f *Fake) EnterRaw() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Raw = true
	// A Restore closed wake. As the real terminal does, a new raw session
	// gets a new one.
	select {
	case <-f.wake:
		f.wake = make(chan struct{})
	default:
	}
	return nil
}

func (f *Fake) Restore() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Raw {
		return
	}
	f.Raw = false
	close(f.wake)
}

// Last returns the most recent frame with ANSI sequences stripped.
func (f *Fake) Last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.Frames) == 0 {
		return ""
	}
	return stripANSI(f.Frames[len(f.Frames)-1])
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			i = j
			continue
		}
		if s[i] == '\r' {
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
