package fakeip

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzJournalLine: no journal text makes parse panic. A line that parse
// takes names an IPv4 address of the pool, at its offset, and a name in
// normal form. A line that line() writes reads back unchanged.
func FuzzJournalLine(f *testing.F) {
	f.Add("1800000000 198.18.7.1 example.com", int64(1800000000), uint32(0), "Example.COM.", false)
	f.Add("1 198.18.7.0 a\n2 198.18.7.255 b", int64(-1), uint32(253), "a b", true)
	f.Add("+5 ::ffff:198.18.7.9 x.test", int64(0), uint32(1<<31), "\x00", false)
	f.Fuzz(func(t *testing.T, raw string, stamp int64, k uint32, name string, wide bool) {
		p := pool24
		if wide {
			p = pool16
		}
		for s := range strings.SplitSeq(raw, "\n") {
			_, a, off, got, ok := parse(p, s)
			if !ok {
				continue
			}
			if !a.Is4() || !p.Contains(a) || addrAt(p, off) != a || off >= usable(p) {
				t.Fatalf("line %q: address %v at offset %d", s, a, off)
			}
			if n, err := Normalise(got); err != nil || n != got {
				t.Fatalf("line %q: name %q not in normal form", s, got)
			}
		}

		n, err := Normalise(name)
		if err != nil {
			return
		}
		a := addrAt(p, k%usable(p))
		l := line(stamp, a, n)
		gs, ga, goff, gn, ok := parse(p, string(l[:len(l)-1]))
		if !ok || gs != stamp || ga != a || goff != k%usable(p) || gn != n {
			t.Fatalf("round trip of %q: %d %v %d %q %v", l, gs, ga, goff, gn, ok)
		}
	})
}

// FuzzReadLines: readLines gives each complete line without its newline,
// counts the bytes up to the last newline, and leaves a torn tail alone.
func FuzzReadLines(f *testing.F) {
	f.Add([]byte("a\nb\n"))
	f.Add([]byte("a\n\ntorn"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		var got []string
		n, err := readLines(bytes.NewReader(data), func(s string) { got = append(got, s) })
		if err != nil {
			t.Fatal(err)
		}
		end := bytes.LastIndexByte(data, '\n') + 1
		if n != int64(end) {
			t.Fatalf("counted %d bytes, last newline ends at %d", n, end)
		}
		want := strings.Split(string(data[:end]), "\n")
		want = want[:len(want)-1]
		if strings.Join(got, "\n") != strings.Join(want, "\n") || len(got) != len(want) {
			t.Fatalf("lines %q, want %q", got, want)
		}
	})
}
