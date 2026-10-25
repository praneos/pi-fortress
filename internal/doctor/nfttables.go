package doctor

import (
	"errors"
	"io/fs"
	"os/exec"
	"strings"
)

// pfTable is the only nft table that pf loads on the Pi
// (internal/render/ruleset.go).
const pfTable = "inet fortress"

// NftTables runs `nft list tables`. A shell of a user that is not root
// often has no /usr/sbin in its PATH, so the fixed path is the fallback.
// The error holds the stderr of nft, because that tells the operator why.
func NftTables() (string, error) {
	bin, err := exec.LookPath("nft")
	if err != nil {
		bin = "/usr/sbin/nft"
	}
	out, err := exec.Command(bin, "list", "tables").Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		err = errors.New(strings.TrimSpace(string(ee.Stderr)))
	}
	return string(out), err
}

// NftTablesRung names each nft table that is not pf's own. The ruleset
// that pf installs starts with `flush ruleset`, and nftables.service
// loads it again at each boot. Thus a table from docker, fail2ban,
// firewalld or the operator does not survive the next apply or boot.
// This is intentional: no other table can send traffic around the
// fence. The rung is a Warn, because the operator must know before the
// tool that made the table stops working. A failure to list is a Warn
// too: it is never an OK.
func NftTablesRung(out string, err error) Result {
	at := func(detail string, st Status) Result {
		return Result{Rung: "nft", Where: "pi", Detail: detail, Status: st}
	}
	switch {
	case errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist):
		return at("cannot list the nft tables: nft is not installed", Warn)
	case err != nil:
		return at("cannot list the nft tables: "+err.Error()+"; run sudo pf doctor", Warn)
	}
	var foreign []string
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "table" {
			continue
		}
		if t := f[1] + " " + f[2]; t != pfTable {
			foreign = append(foreign, t)
		}
	}
	if len(foreign) == 0 {
		return at("no nft table other than pf's "+pfTable, OK)
	}
	return at("nft tables that pf does not own: "+strings.Join(foreign, ", ")+
		"; the next apply or boot removes them, because pf replaces the whole ruleset (docs/user_guide/pi_setup.md)", Warn)
}
