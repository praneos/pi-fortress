package httpwire

import (
	"bufio"
	"bytes"
	"io"
	"strconv"
	"strings"
)

type chunkedReader struct {
	br      *bufio.Reader
	n       int64
	done    bool
	err     error
	started bool
	excess  int64
	// last says that Read found the last chunk after data that it already
	// had. The trailers come in the next call.
	last bool
}

// maxChunkExcess is the limit on the framing count of overhead.
const maxChunkExcess = 16 * 1024

func newChunkedReader(br *bufio.Reader) io.Reader {
	return &chunkedReader{br: br}
}

// Read gives the data of all the chunks that p has space for, as net/http
// does. Before, it gave one chunk for each call. Thus a body in chunks of
// one byte cost one call for each byte in each filter above it. After the
// first data, Read continues only on bytes that are already in the
// buffer. It never waits for more input when it has data to give, so a
// stream of small chunks still passes immediately.
func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.done {
		return 0, io.EOF
	}
	if c.last {
		return c.trailers()
	}
	n := 0
	for {
		if n > 0 && (n == len(p) || !c.more()) {
			return n, nil
		}
		if c.n == 0 {
			size, err := c.next()
			if err != nil {
				if n > 0 {
					// The data before the error goes out first, and the next call
					// gives the error. This is the order that one chunk for each
					// call gave.
					c.err = err
					return n, nil
				}
				return c.fail(err)
			}
			if size == 0 {
				if n > 0 {
					c.last = true
					return n, nil
				}
				return c.trailers()
			}
			c.n = size
			continue
		}
		q := p[n:]
		if int64(len(q)) > c.n {
			q = q[:c.n]
		}
		k, err := c.br.Read(q)
		n += k
		c.n -= int64(k)
		if err != nil && err != io.EOF {
			c.err = err
			return n, err
		}
		if err == io.EOF && c.n > 0 {
			c.err = io.ErrUnexpectedEOF
			return n, c.err
		}
		if k == 0 {
			return n, nil
		}
	}
}

// more says whether Read can continue without a wait for input: the rest
// of the chunk data, or else the framing before the next chunk, is in the
// buffer. The framing is the CRLF after the data and the full size line.
// This is chunkHeaderAvailable of net/http, with the CRLF added.
func (c *chunkedReader) more() bool {
	if c.n > 0 {
		return c.br.Buffered() > 0
	}
	b, _ := c.br.Peek(c.br.Buffered())
	i := bytes.IndexByte(b, '\n')
	return i >= 0 && bytes.IndexByte(b[i+1:], '\n') >= 0
}

// next reads the framing before the data of a chunk and returns the size
// of the chunk.
func (c *chunkedReader) next() (int64, error) {
	if c.started {
		// The CRLF after the data of a chunk must be exactly that. Before, the
		// code read a line and dropped it, so anything up to the next LF could
		// stand in for it.
		end, err := c.framing()
		if err != nil {
			return 0, err
		}
		if end != "" {
			return 0, ErrBadRequest
		}
	}
	c.started = true
	// net/http reads the size line in a 4 KiB buffer and refuses a longer
	// line. Before, this code read up to 8 KiB. Thus a long chunk
	// extension framed here and the stdlib refused the body.
	line, err := c.framingMax(maxChunkLine)
	if err != nil {
		return 0, err
	}
	n, err := chunkSize(line)
	if err != nil {
		return 0, err
	}
	if !c.overhead(len(line), n) {
		return 0, ErrBadRequest
	}
	return n, nil
}

// overhead counts the framing of one chunk as net/http does: the size
// line and the CRLF after the data, less 16 bytes and two per data byte.
// The count does not go below zero. It returns false when the count
// passes maxChunkExcess. net/http refuses that body, so this code refuses
// it too. A chunk of 1 MiB or more always sets the count to zero. That
// step also keeps 2*n in range.
func (c *chunkedReader) overhead(line int, n int64) bool {
	c.excess += int64(line) + 2
	if n >= 1<<20 {
		c.excess = 0
	} else {
		c.excess = max(c.excess-16-2*n, 0)
	}
	return c.excess <= maxChunkExcess
}

// maxTrailerBytes is the limit on the trailer block: each trailer line
// with its CRLF, and the CRLF of the empty line that ends the block.
// net/http requires the full block in the buffer of its connection
// reader, which is 4096 bytes (body.readTrailer in transfer.go). It
// refuses a longer block. Before, this code allowed 64 KiB. Thus a
// streamed body with a trailer block of 4 to 64 KiB read clean here, and
// a Go peer refused it.
const maxTrailerBytes = 4096

// trailers reads the trailer block after the last chunk, to the empty
// line that ends the body.
func (c *chunkedReader) trailers() (int, error) {
	// The count starts with the CRLF of the empty line that ends the block.
	trailer := 2
	for {
		t, err := c.framing()
		if err != nil {
			return c.fail(err)
		}
		if t == "" {
			c.done = true
			return 0, io.EOF
		}
		if trailer += len(t) + 2; trailer > maxTrailerBytes {
			return c.fail(ErrHeaderLimit)
		}
		// The trailer block was counted against the header budget but never
		// read. It was the one place where arbitrary bytes passed through the
		// parser unexamined.
		if err := trailerLine(t); err != nil {
			return c.fail(err)
		}
	}
}

// framing reads a line that the chunk framing requires. An EOF in the
// middle of it is a truncated body, not a finished one. If returned as
// io.EOF, it reaches io.ReadAll as a clean end, and a half-sent upload
// then looks the same as a whole one.
func (c *chunkedReader) framing() (string, error) {
	return c.framingMax(maxLineBytes)
}

// framingMax is framing with a different line limit.
func (c *chunkedReader) framingMax(max int) (string, error) {
	line, err := readLineMax(c.br, max)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return line, err
}

// trailerLine holds a trailer to the shape of a header field. The fence
// drops trailers and does not forward them, so this is strictness and
// not a desync. But a parser that discards what it cannot read is one
// refactor away from a parser that forwards it.
func trailerLine(t string) error {
	name, value, ok := strings.Cut(t, ":")
	if !ok || name == "" || strings.TrimSpace(name) != name || !isToken(name) || hasCTL(value) {
		return ErrBadRequest
	}
	return nil
}

// chunkSize reads the size line as 1*HEXDIG, with the extension cut off
// and nothing else allowed. ParseInt would take a sign, and TrimSpace any
// Unicode space. Thus "+3", "-0" and " 3 " all framed here and the stdlib
// refused them. contentLength guards the header against the same
// disagreement.
func chunkSize(line string) (int64, error) {
	line, ext, _ := strings.Cut(line, ";")
	// The extension was cut off and never examined, so a control byte got
	// through in it. Nothing here uses an extension. A refusal of what cannot
	// be a valid extension costs nothing real.
	if hasCTL(ext) {
		return 0, ErrBadRequest
	}
	line = strings.Trim(line, " \t")
	// 16 hex digits is a full uint64, and the stdlib stops there. A longer
	// run parses to a normal size here and the stdlib refuses it. That is
	// the same disagreement again.
	if line == "" || len(line) > 16 {
		return 0, ErrBadRequest
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if (c < '0' || c > '9') && (c|0x20 < 'a' || c|0x20 > 'f') {
			return 0, ErrBadRequest
		}
	}
	n, err := strconv.ParseInt(line, 16, 64)
	if err != nil {
		return 0, ErrBadRequest
	}
	return n, nil
}

func (c *chunkedReader) fail(err error) (int, error) {
	c.err = err
	return 0, err
}

// lengthReader is io.LimitReader for a Content-Length body, except that
// an EOF before n bytes is io.ErrUnexpectedEOF. LimitReader reads a body
// cut short as a short clean body. The buffered path then rewrote
// Content-Length to fit it, and a half-sent upload went out whole.
type lengthReader struct {
	r io.Reader
	n int64
}

func (l *lengthReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	if err == io.EOF && l.n > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

type ChunkedWriter struct {
	w io.Writer
}

func NewChunkedWriter(w io.Writer) *ChunkedWriter {
	return &ChunkedWriter{w: w}
}

func (c *ChunkedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var buf bytes.Buffer
	buf.WriteString(strconv.FormatInt(int64(len(p)), 16))
	buf.WriteString("\r\n")
	buf.Write(p)
	buf.WriteString("\r\n")
	if _, err := c.w.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ChunkedWriter) Close() error {
	_, err := io.WriteString(c.w, "0\r\n\r\n")
	return err
}

// ScanPump is the read half that the stream filters share. It fills Buf
// from Src, calls Scan to move what can leave into Out, and gives Out to
// the caller. Scan runs one time per source read, including the read
// that sets EOF.
type ScanPump struct {
	Src  io.Reader
	Scan func()
	Buf  []byte
	Out  []byte
	EOF  bool

	chunk []byte
}

func (r *ScanPump) Read(p []byte) (int, error) {
	for len(r.Out) == 0 {
		if r.EOF {
			return 0, io.EOF
		}
		if r.chunk == nil {
			r.chunk = make([]byte, 32*1024)
		}
		n, err := r.Src.Read(r.chunk)
		r.Buf = append(r.Buf, r.chunk[:n]...)
		if err == io.EOF {
			r.EOF = true
		} else if err != nil {
			return 0, err
		}
		r.Scan()
	}
	n := copy(p, r.Out)
	r.Out = r.Out[n:]
	return n, nil
}

// Scrubber replaces every occurrence of each Old with its New in a byte
// stream, including matches that straddle Read boundaries. Counts
// records how many times each pair matched.
type Scrubber struct {
	ScanPump
	pairs  [][2][]byte
	keep   int
	Counts []int
}

// NewScrubber replaces pairs[i][0] with pairs[i][1] in a stream, in one
// pass per read. It holds back maxLen-1 bytes, so it still catches an
// occurrence split across reads.
func NewScrubber(src io.Reader, pairs [][2][]byte) *Scrubber {
	keep := 0
	for _, p := range pairs {
		if len(p[0]) > keep {
			keep = len(p[0])
		}
	}
	if keep > 0 {
		keep--
	}
	s := &Scrubber{pairs: pairs, keep: keep, Counts: make([]int, len(pairs))}
	s.Src, s.Scan = src, s.scan
	return s
}

func (s *Scrubber) scan() {
	if len(s.pairs) == 0 {
		s.Out = append(s.Out[:0], s.Buf...)
		s.Buf = s.Buf[:0]
		return
	}
	safe := len(s.Buf)
	if !s.EOF {
		safe -= s.holdback(s.Buf)
		if safe <= 0 {
			return
		}
	}
	var pos int
	s.Out, pos = replaceUpTo(s.Out[:0], s.Buf, safe, s.pairs, s.Counts)
	tail := copy(s.Buf, s.Buf[pos:])
	s.Buf = s.Buf[:tail]
}

// Push is the scrubber driven from outside, not from a read of Src. p is
// the next part of the stream, and Push appends to dst what can leave
// now. final says that p ends the stream. Then nothing is held back, and
// the scrubber is ready for a new stream after it. Counts continue to add
// up. The websocket relay gives it the payload of one frame at a time, so
// it still catches a value split across two frames of a message.
func (s *Scrubber) Push(dst, p []byte, final bool) []byte {
	s.Buf = append(s.Buf, p...)
	s.EOF = final
	s.scan()
	dst = append(dst, s.Out...)
	s.Out = s.Out[:0]
	s.EOF = false
	return dst
}

// holdback is how many trailing bytes of buf could still be the start of
// a pattern and must wait for the next read. Usually zero, so small
// server-sent events pass through immediately, not one event late. buf
// is a parameter, not s.Buf, because promoted selectors cost it its
// inlining.
func (s *Scrubber) holdback(buf []byte) int {
	n := min(s.keep, len(buf))
	for k := n; k > 0; k-- {
		tail := buf[len(buf)-k:]
		for _, p := range s.pairs {
			if len(p[0]) > k && bytes.HasPrefix(p[0], tail) {
				return k
			}
		}
	}
	return 0
}
