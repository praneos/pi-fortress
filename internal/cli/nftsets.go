package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"pi-fortress/internal/nftsets"
	"pi-fortress/internal/policycompile"
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
//
// policy runs at the restart of pf dns, while pf dns is stopped. It
// flushes each resolved set whose DNS policy changed since the last
// apply (nftsets.Policy).
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
	case "save", "restore", "policy":
	default:
		fmt.Fprintf(stderr, "pf nftsets: unknown verb %q\n", verb)
		nftsetsUsage(stderr)
		return 2
	}
	fs := newFlags("nftsets "+verb, stderr)
	table := fs.String("table", "inet fortress", "nft table holding the sets")
	file := fs.String("file", "", "carry file: written by save, read by restore")
	config := fs.String("config", "", "policy: the pf dns config that pf dns starts on next")
	state := fs.String("state", "", "policy: the fingerprints of the last apply, read and then written")
	policyDir := fs.String("policy", "", "policy: the policy dir that pf compile reads (the operator lists)")
	if code, ok := parse(fs, args[1:]); !ok {
		return code
	}
	if verb == "policy" {
		if *config == "" || *state == "" || *policyDir == "" {
			nftsetsUsage(stderr)
			return 2
		}
		return nftsetsPolicy(nftsets.Exec, *table, *config, *policyDir, *state, stdout, stderr)
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
	fmt.Fprintln(w, "       pf nftsets policy --config DNS_JSON --policy DIR --state FILE [--table 'inet fortress']")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  save     write the resolved-address sets and their remaining timeouts")
	fmt.Fprintln(w, "  restore  re-add them to the sets the loaded ruleset still has")
	fmt.Fprintln(w, "  policy   flush each resolved-address set whose DNS policy changed; run while pf dns is stopped")
}

func nftsetsSave(table, file string, stderr io.Writer) int {
	// The time before the listings, not after. Restore subtracts the time
	// since savedAt from each remaining time. A savedAt after the listings
	// would give each element the time of the listings again.
	savedAt := time.Now()
	sets, err := nftsets.Save(nftsets.Exec, table)
	if err != nil {
		return fail(stderr, err)
	}
	var b bytes.Buffer
	if err := nftsets.Format(&b, savedAt, sets); err != nil {
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

// nftsetsPolicy compares the DNS policy of each resolved set in config
// and the operator lists in policyDir with the fingerprints in state,
// flushes each set that changed, and writes the new fingerprints. A feed
// change alone does not flush (nftsets.Policy). If it cannot read config, it flushes all
// resolved sets: it cannot say which policy changed. If the flush fails,
// it keeps the old state, so the next apply sees the change again.
func nftsetsPolicy(run nftsets.Runner, table, config, policyDir, state string, stdout, stderr io.Writer) int {
	var operator []string
	for _, name := range policycompile.DNSInputs() {
		operator = append(operator, filepath.Join(policyDir, name))
	}
	var fps map[string]string
	data, err := os.ReadFile(config)
	if err == nil {
		fps, err = nftsets.Policy(data, operator, os.ReadFile)
	}
	if err != nil {
		names, lerr := nftsets.Names(run, table)
		if lerr == nil {
			_, lerr = nftsets.Flush(run, table, names)
		}
		if lerr != nil {
			fmt.Fprintf(stderr, "pf nftsets: flushing the resolved-address sets: %v\n", lerr)
		}
		return fail(stderr, err)
	}
	before := map[string]string{}
	if f, err := os.Open(state); err == nil {
		before, err = nftsets.ParseState(f)
		f.Close()
		if err != nil {
			return fail(stderr, err)
		}
	} else if !os.IsNotExist(err) {
		return fail(stderr, err)
	}
	flushed, err := nftsets.Flush(run, table, nftsets.Changed(before, fps))
	if err != nil {
		return fail(stderr, err)
	}
	var b bytes.Buffer
	if err := nftsets.FormatState(&b, fps); err != nil {
		return fail(stderr, err)
	}
	tmp := state + ".new"
	if err := os.WriteFile(tmp, b.Bytes(), 0o600); err != nil {
		return fail(stderr, err)
	}
	if err := os.Rename(tmp, state); err != nil {
		return fail(stderr, err)
	}
	for _, s := range flushed {
		fmt.Fprintf(stdout, "pi-fortress: the DNS policy of %s changed; its resolved addresses were removed\n", s)
	}
	return 0
}
