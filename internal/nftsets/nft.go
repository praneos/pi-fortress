package nftsets

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner is how this package uses nft: the arguments, the stdin data, and
// what nft printed. It is a function, not a direct exec. Thus tests can
// run the capture, the batching and the script without root or a kernel.
type Runner func(stdin string, args ...string) (string, error)

// nftTimeout limits one nft call. A capture or a re-add that hangs must
// not stop the apply behind it. An empty set is the old behaviour and the
// safe answer. A stuck apply is neither.
const nftTimeout = 20 * time.Second

// Exec is the Runner that shells out to nft.
func Exec(stdin string, args ...string) (string, error) {
	cmd := exec.Command("nft", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return out.String(), fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
		}
		return out.String(), nil
	case <-time.After(nftTimeout):
		_ = cmd.Process.Kill()
		<-done
		return "", fmt.Errorf("nft %s: timed out", strings.Join(args, " "))
	}
}

// tableArgs splits a table name in the nft command-line format,
// "inet fortress", into its two words.
func tableArgs(table string) []string { return strings.Fields(table) }

// Names lists the sets the table currently has.
func Names(run Runner, table string) ([]string, error) {
	out, err := run("", append([]string{"list", "sets", "table"}, tableArgs(table)...)...)
	if err != nil {
		return nil, err
	}
	return SetNames(out), nil
}

// Save captures each carried set in the table, and each element with the
// time that nft gives as remaining.
//
// It uses one listing for each set, not one for the full table. `list
// table` also prints blacklist_v4: hundreds of thousands of compiled
// elements that this code does not read.
func Save(run Runner, table string) ([]Set, error) {
	names, err := Names(run, table)
	if err != nil {
		return nil, err
	}
	var sets []Set
	for _, name := range names {
		if !Carried(name) {
			continue
		}
		out, err := run("", append(append([]string{"list", "set"}, tableArgs(table)...), name)...)
		if err != nil {
			return nil, err
		}
		s, err := ParseSet(out)
		if err != nil {
			return nil, err
		}
		// Use the requested name, not the name that the listing printed.
		// These elements must go back into the set that they came from.
		// A parsed name is less trusted than that.
		s.Name = name
		sets = append(sets, s)
	}
	return sets, nil
}

// Restore adds the carried elements again to the sets with the same name
// that the newly loaded ruleset still has. If a set is gone (a segment that
// the operator deleted between the two rulesets), its elements are lost.
//
// All of it is one `nft -f -` transaction. Thousands of elements are normal
// on a busy segment. A fork for each address would cost more than the
// reload that it repairs.
func Restore(run Runner, table string, sets []Set) (int, error) {
	names, err := Names(run, table)
	if err != nil {
		return 0, err
	}
	keep := make(map[string]bool, len(names))
	for _, n := range names {
		keep[n] = true
	}
	script, n := Script(table, sets, keep)
	if n == 0 {
		return 0, nil
	}
	if _, err := run(script, "-f", "-"); err != nil {
		return 0, err
	}
	return n, nil
}
