package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"pi-fortress/internal/nftsets"
)

// pf nftsets is the helper of apply.sh around the ruleset reload. `nft
// -f` replaces the full table. Thus the address sets of the resolver
// come back empty. The gate then drops a client with its own DNS cache
// until that cache expires. save writes the elements out before the
// load. restore puts them back after the load, each with the remaining
// part of its timeout.
//
// It is a pf subcommand for the same reason as render and compile. The
// bugs would be in the parse: the element spelling of nft, its duration
// units, and the arithmetic that must never give an element more life
// than it had. apply.sh keeps only the plumbing.
func runNFTSets(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		nftsetsUsage(stderr)
		return 2
	}
	verb := args[0]
	switch verb {
	case "-h", "--help", "help":
		// On stderr, the same as all other pf usage. The flag package puts a
		// refusal there, and help reads the same as a refusal.
		nftsetsUsage(stderr)
		return 0
	case "save", "restore":
	default:
		fmt.Fprintf(stderr, "pf nftsets: unknown verb %q\n", verb)
		nftsetsUsage(stderr)
		return 2
	}
	fs := newFlags("nftsets "+verb, stderr)
	table := fs.String("table", "inet fortress", "nft table holding the sets")
	file := fs.String("file", "", "carry file: written by save, read by restore")
	if code, ok := parse(fs, args[1:]); !ok {
		return code
	}
	if *file == "" {
		nftsetsUsage(stderr)
		return 2
	}
	if verb == "save" {
		return nftsetsSave(*table, *file, stderr)
	}
	return nftsetsRestore(*table, *file, stdout, stderr)
}

func nftsetsUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: pf nftsets save|restore --file FILE [--table 'inet fortress']")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  save     write the resolved-address sets and their remaining timeouts")
	fmt.Fprintln(w, "  restore  re-add them to the sets the loaded ruleset still has")
}

func nftsetsSave(table, file string, stderr io.Writer) int {
	sets, err := nftsets.Save(nftsets.Exec, table)
	if err != nil {
		return fail(stderr, err)
	}
	var b bytes.Buffer
	if err := nftsets.Format(&b, time.Now(), sets); err != nil {
		return fail(stderr, err)
	}
	// 0600, not the guess of the umask. The file names each address that
	// this box resolved for each segment. That is the query log by a
	// different route. restore sends set names from it directly to nft.
	if err := os.WriteFile(file, b.Bytes(), 0o600); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func nftsetsRestore(table, file string, stdout, stderr io.Writer) int {
	f, err := os.Open(file)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing was captured: a first apply, or a save that already
			// reported its own failure. An empty set is what the box did
			// before this existed. Thus it is not an error here.
			return 0
		}
		return fail(stderr, err)
	}
	defer f.Close()
	sets, err := nftsets.Parse(f, time.Now())
	if err != nil {
		return fail(stderr, err)
	}
	n, err := nftsets.Restore(nftsets.Exec, table, sets)
	if err != nil {
		return fail(stderr, err)
	}
	if n > 0 {
		fmt.Fprintf(stdout, "pi-fortress: %d resolved addresses carried across the reload\n", n)
	}
	return 0
}
