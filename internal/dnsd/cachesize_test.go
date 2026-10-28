package dnsd

import (
	"strconv"
	"testing"
	"time"
)

// The cache counts entries, not bytes, and an answer over TCP can be 64
// KiB. A client can ask for defaultCacheSize names in a zone that it
// controls, each with a large TXT set, in ten seconds at the nft rate.
// Without a limit for each entry, the cache then held approximately 125
// MiB. The DoT stub, which forwards for each segment, has MemoryMax=128M.
func TestCacheKeepsNoLargeAnswer(t *testing.T) {
	c := newCache(defaultCacheSize, time.Now)
	gen := c.generation()
	big := make([]byte, maxMsg)
	for i := range defaultCacheSize {
		c.put(cacheKey{name: "n" + strconv.Itoa(i) + ".example", qtype: 16}, big, time.Hour, gen)
	}
	held := 0
	for _, e := range c.m {
		held += len(e.msg)
	}
	if held > 32<<20 {
		t.Fatalf("the cache holds %d MiB of large answers", held>>20)
	}
	// An answer of an ordinary size is still cached.
	k := cacheKey{name: "ok.example", qtype: 1}
	c.put(k, make([]byte, 512), time.Hour, gen)
	if _, _, ok := c.get(k); !ok {
		t.Fatal("a 512-byte answer was not cached")
	}
}
