package httpwire

import "bytes"

// Index is bytes.Index tuned for needles whose first byte is a common
// letter. bytes.Index scans with memchr on byte 0 and verifies each hit.
// With an 's' or 'g', every twentieth byte is a hit, and the scan runs at
// memory-compare speed. A scan for the rarest byte of the needle keeps it
// in memchr. Same result as bytes.Index.
func Index(src, needle []byte) int {
	n := len(needle)
	if n < 2 || len(src) < n {
		if n == 0 {
			return 0
		}
		return bytes.Index(src, needle)
	}
	k := rareOffset(needle)
	c := needle[k]
	// Search only where a full needle fits: byte k must sit at
	// [k, len(src)-n+k].
	for i := k; i <= len(src)-n+k; {
		j := bytes.IndexByte(src[i:len(src)-n+k+1], c)
		if j < 0 {
			return -1
		}
		p := i + j - k
		if bytes.Equal(src[p:p+n], needle) {
			return p
		}
		i += j + 1
	}
	return -1
}

func rareOffset(needle []byte) int {
	best, bestScore := 0, 255
	for i, c := range needle {
		if s := byteFreq[c]; int(s) < bestScore {
			best, bestScore = i, int(s)
		}
	}
	return best
}

// byteFreq ranks how often a byte appears in English text and JSON. Low
// is rare. Only the order is important, not the values.
var byteFreq = func() (t [256]uint8) {
	for i := range t {
		t[i] = 40
	}
	for i := 'A'; i <= 'Z'; i++ {
		t[i] = 20
	}
	for i := '0'; i <= '9'; i++ {
		t[i] = 60
	}
	common := "etaoinsrhldcumfpgwybvkxjqz"
	for i, c := range []byte(common) {
		t[c] = uint8(200 - i*6)
	}
	for _, c := range []byte(" \n\r\t\",:{}[].") {
		t[c] = 220
	}
	for _, c := range []byte("_-/=+") {
		t[c] = 80
	}
	return
}()

func Contains(src, needle []byte) bool { return Index(src, needle) >= 0 }

// ReplaceAll appends src to dst, with each occurrence of pairs[i][0]
// replaced by pairs[i][1], in one left-to-right pass. The leftmost
// occurrence wins, and at the same start the longest wins. The order of
// pairs never decides. No byte of any occurrence survives. An occurrence
// that starts inside a replacement and runs past its end is covered too
// (see cover). counts[i], when non-nil, is incremented per replacement of
// pair i.
func ReplaceAll(dst, src []byte, pairs [][2][]byte, counts []int) []byte {
	dst, pos := replaceUpTo(dst, src, len(src), pairs, counts)
	return append(dst, src[pos:]...)
}

// replaceUpTo replaces occurrences that start before safe. It appends src
// up to max(safe, end of last replacement). It returns how much of src it
// consumed. The caller carries the rest, because an occurrence split
// across two reads can still begin there. safe == len(src) means src is
// all there is.
func replaceUpTo(dst, src []byte, safe int, pairs [][2][]byte, counts []int) ([]byte, int) {
	var stack [16]int
	var next []int
	if len(pairs) <= len(stack) {
		next = stack[:len(pairs)]
	} else {
		next = make([]int, len(pairs))
	}
	for i, p := range pairs {
		next[i] = -1
		if len(p[0]) > 0 {
			next[i] = Index(src, p[0])
		}
	}
	pos := 0
	var heads *[256]bool // built on the first hit; most bodies have none
	for {
		best, bi := leftmost(next, pairs)
		if best < 0 || best >= safe {
			break
		}
		if heads == nil {
			heads = headsOf(pairs)
		}
		end, ok := cover(src, best, best+len(pairs[bi][0]), pairs, heads, safe == len(src))
		if !ok {
			// An overlapping occurrence can run past the end of the data read so
			// far. Stop before this one. The caller carries it into the next read,
			// where cover can see all of it.
			return append(dst, src[pos:best]...), best
		}
		dst = append(dst, src[pos:best]...)
		dst = append(dst, pairs[bi][1]...)
		if counts != nil {
			counts[bi]++
		}
		pos = best + len(pairs[bi][0])
		for pos < end {
			i, e := overlapAt(src, best, pos, pairs, heads)
			r := pairs[i][1]
			if len(r) == len(pairs[i][0]) {
				r = r[len(r)-(e-pos):]
			}
			dst = append(dst, r...)
			if counts != nil {
				counts[i]++
			}
			pos = e
		}
		advance(next, src, pos, pairs)
	}
	if pos < safe {
		dst = append(dst, src[pos:safe]...)
		pos = safe
	}
	return dst, pos
}

// leftmost is the next occurrence in next: the lowest start, and at the
// same start the longest pattern. best is -1 when no occurrence is left.
func leftmost(next []int, pairs [][2][]byte) (best, bi int) {
	best, bi = -1, -1
	for i, n := range next {
		if n >= 0 && (best < 0 || n < best || (n == best && len(pairs[i][0]) > len(pairs[bi][0]))) {
			best, bi = n, i
		}
	}
	return best, bi
}

// advance finds the next occurrence again for each pattern whose last
// occurrence starts before pos. The replacement consumed that start.
func advance(next []int, src []byte, pos int, pairs [][2][]byte) {
	for i, n := range next {
		if n >= 0 && n < pos {
			next[i] = -1
			if j := Index(src[pos:], pairs[i][0]); j >= 0 {
				next[i] = pos + j
			}
		}
	}
}

// cover is where the region replaced from start must end: past end, for
// as long as an occurrence starts inside it and runs beyond it. Without
// this, if the head of a live value is inside a different replacement,
// its tail would go out as is. ok is false when an occurrence might run
// past len(src) and more input may follow (!final).
func cover(src []byte, start, end int, pairs [][2][]byte, heads *[256]bool, final bool) (int, bool) {
	for pos := end; ; {
		for s := start + 1; s < pos; s++ {
			if !heads[src[s]] {
				continue
			}
			for _, p := range pairs {
				if len(p[0]) == 0 || s+len(p[0]) <= pos {
					continue
				}
				if !final && s+len(p[0]) > len(src) && bytes.HasPrefix(p[0], src[s:]) {
					return 0, false
				}
			}
		}
		_, e := overlapAt(src, start, pos, pairs, heads)
		if e <= pos {
			return pos, true
		}
		pos = e
	}
}

// overlapAt finds, from the left, the first occurrence that starts in
// (start, pos) and ends past pos, the longest at that start. e <= pos
// when there is none.
func overlapAt(src []byte, start, pos int, pairs [][2][]byte, heads *[256]bool) (int, int) {
	for s := start + 1; s < pos; s++ {
		if !heads[src[s]] {
			continue
		}
		bi, be := -1, pos
		for i, p := range pairs {
			if e := s + len(p[0]); len(p[0]) > 0 && e > be && bytes.HasPrefix(src[s:], p[0]) {
				bi, be = i, e
			}
		}
		if bi >= 0 {
			return bi, be
		}
	}
	return -1, pos
}

// headsOf is the set of bytes that live values start with. An occurrence
// can begin only on one of them, so cover and overlapAt skip all other
// offsets. A check of each offset of each hit against all values made a
// body full of hits run at a few MB/s with 64 enrolled values
// (BenchmarkScrubberDense). Real keys share a small number of first bytes
// that are rare inside a key. Thus almost all offsets are skipped.
func headsOf(pairs [][2][]byte) *[256]bool {
	var h [256]bool
	for _, p := range pairs {
		if len(p[0]) > 0 {
			h[p[0][0]] = true
		}
	}
	return &h
}
