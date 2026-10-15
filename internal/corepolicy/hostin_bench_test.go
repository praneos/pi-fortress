package corepolicy

import (
	"fmt"
	"strings"
	"testing"
)

func bigTable(n int) map[string]struct{} {
	t := make(map[string]struct{}, n)
	for i := range n {
		t[fmt.Sprintf("host%d.example%d.com", i, i)] = struct{}{}
	}
	t["github.com"] = struct{}{}
	return t
}

// hostInScan is HostIn as it was before the label walk. The fuzz test
// uses it to prove that the two give the same answers.
func hostInScan(name string, table map[string]struct{}) bool {
	name = normHost(name)
	if _, ok := table[name]; ok {
		return true
	}
	for item := range table {
		if strings.HasSuffix(name, "."+item) {
			return true
		}
	}
	return false
}

func BenchmarkHostInMiss(b *testing.B) {
	for _, n := range []int{18, 1000, 50000} {
		t := bigTable(n)
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				HostIn("telemetry.evil-cdn.example", t)
			}
		})
	}
}

func BenchmarkHostInScanMiss(b *testing.B) {
	for _, n := range []int{18, 1000, 50000} {
		t := bigTable(n)
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				hostInScan("telemetry.evil-cdn.example", t)
			}
		})
	}
}

// coreListedScan is coreListed as it was before the label walk.
func (f *Forward) coreListedScan(name string) bool {
	if _, ok := f.hosts[name]; ok {
		return true
	}
	for item := range f.suffix {
		if strings.HasSuffix(name, "."+item) {
			return true
		}
	}
	return false
}

// FuzzHostInMatchesScan is the full proof for the label walk. The rewrite
// only makes the code faster. Thus, if the two disagree on a name and a
// table, the new code has a bug. The exception is a name with an empty
// label.
func FuzzHostInMatchesScan(f *testing.F) {
	for _, s := range []string{"github.com", "a.github.com", "notgithub.com", "", ".", "a..b", "A.GitHub.Com.", "x.y.z"} {
		f.Add(s, "github.com\n.b\n\nb\nx.y.z")
	}
	f.Fuzz(func(t *testing.T, name, list string) {
		table := map[string]struct{}{}
		suffix := map[string]struct{}{}
		for i, e := range strings.Split(list, "\n") {
			table[e] = struct{}{}
			if i%2 == 0 {
				suffix[e] = struct{}{}
			}
		}
		// The scan read an empty label as a subdomain. The walk always refuses
		// such a name. That is the only place where the two disagree.
		if emptyLabel(normHost(name)) {
			if HostIn(name, table) {
				t.Fatalf("HostIn(%q) matched a name with an empty label", name)
			}
		} else if got, want := HostIn(name, table), hostInScan(name, table); got != want {
			t.Fatalf("HostIn(%q) = %v, scan = %v", name, got, want)
		}
		fw := &Forward{hosts: table, suffix: suffix}
		if got, want := fw.coreListed(name), fw.coreListedScan(name); got != want {
			t.Fatalf("coreListed(%q) = %v, scan = %v", name, got, want)
		}
	})
}
