package feedstage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"

	"pi-fortress/internal/eyeball"
)

// The hard byte caps of the staged files. Each is far above a real file,
// and below what the memory caps of the root units hold. A list and
// feeds.map also have a smaller cap: the bytes of their line cap (byteCap).
// They are variables only so that a test can make them small.
var (
	listCap    int64 = 64 << 20
	mapCap     int64 = 96 << 20
	eyeballCap int64 = 96 << 20
	reportCap  int64 = 1 << 20
	runCap     int64 = 64
)

// Config is one import.
type Config struct {
	// StateDir has the stage directory (StageName) in it. The default is
	// the StateDir constant.
	StateDir string
	// OutDir is generated/ of the policy directory.
	OutDir string
	Limits Limits
	// Run is the run id of the request of this run.
	Run string
	// UID is the owner that each staged file must have: the uid of
	// pf-feeds. -1 skips the check (tests).
	UID int
}

// Result tells what Import did.
type Result struct {
	// Imported is true when the set passed and is in OutDir.
	Imported bool
	// IPs and Domains count the entries of the imported agent lists, for
	// the audit log. -1 means that the list was not in the set.
	IPs, Domains int
	// Report is the report that Import wrote into OutDir.
	Report []string
	// Refused tells why the set was refused, or "".
	Refused string
}

// ErrNoRun means that the stage holds no set of this run: the download did
// not get to its end, or it ran for a different request. Import then
// writes nothing.
var ErrNoRun = errors.New("the stage has no output of this run")

// ErrRefused means that a staged file failed the check. Import then wrote
// only the report.
var ErrRefused = errors.New("the staged set was refused")

// list is one staged list and its check.
type list struct {
	name string
	kind Kind
	max  func(Limits) int
}

func lists() []list {
	ips := func(l Limits) int { return l.MaxIPs }
	doms := func(l Limits) int { return l.MaxDomains }
	return []list{
		{IPsFile, KindIPs, ips},
		{DomainsFile, KindBlockDomains, doms},
		{HouseDomainsFile, KindNames, doms},
		{HouseVPNFile, KindNames, doms},
	}
}

// Import reads the stage of the download, checks each file, and writes the
// set into c.OutDir. One failure in any file refuses the full set: then
// only the report is written, with a "FAIL stage" line first. A list that
// is not in the stage keeps its copy in OutDir. Root never writes into the
// stage, and reads only the fixed names there.
func Import(c Config) (Result, error) {
	res := Result{IPs: -1, Domains: -1}
	stateDir := c.StateDir
	if stateDir == "" {
		stateDir = StateDir
	}
	st, err := openStage(stateDir)
	if err != nil {
		return res, err
	}
	defer st.Close()
	run, err := readStaged(st, RunFile, runCap, false, c.UID)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return res, ErrNoRun
	case err != nil:
		return refuse(c, res, RunFile+": "+err.Error(), nil)
	case !ValidRun(c.Run) || string(run) != c.Run+"\n":
		return res, ErrNoRun
	}
	var report []string
	if raw, err := readStaged(st, ReportFile, reportCap, true, c.UID); err == nil {
		report = FilterReport(raw)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return refuse(c, res, ReportFile+": "+err.Error(), nil)
	}

	var files []File
	items := map[string]struct{}{}
	total := 0
	var domains []string
	hasDomains := false
	for _, l := range lists() {
		limit := l.max(c.Limits)
		raw, err := readStaged(st, l.name, byteCap(limit, l.kind.lineMax(), listCap), false, c.UID)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return refuse(c, res, l.name+": "+err.Error(), report)
		}
		got, err := CheckList(l.kind, raw, limit)
		if err != nil {
			return refuse(c, res, l.name+": "+err.Error(), report)
		}
		for _, it := range got {
			items[it] = struct{}{}
		}
		total += len(got)
		switch l.name {
		case IPsFile:
			res.IPs = len(got)
		case DomainsFile:
			res.Domains = len(got)
			domains, hasDomains = got, true
		}
		// CheckList passed, so raw is the lines of got, each with its
		// newline: no second copy.
		files = append(files, File{l.name, raw})
	}
	if raw, err := readStaged(st, FeedsMapFile, byteCap(total, mapLineMax, mapCap), false, c.UID); err == nil {
		if err := CheckMap(raw, items, c.Limits.FeedIDs, total); err != nil {
			return refuse(c, res, FeedsMapFile+": "+err.Error(), report)
		}
		files = append(files, File{FeedsMapFile, raw})
	} else if !errors.Is(err, fs.ErrNotExist) {
		return refuse(c, res, FeedsMapFile+": "+err.Error(), report)
	}
	if raw, err := readStaged(st, EyeballFile, eyeballCap, false, c.UID); err == nil {
		t, err := eyeball.Parse(bytes.NewReader(raw))
		if err != nil {
			return refuse(c, res, EyeballFile+": "+err.Error(), report)
		}
		var b bytes.Buffer
		if err := t.Encode(&b); err != nil {
			return res, err
		}
		files = append(files, File{EyeballFile, b.Bytes()})
	} else if !errors.Is(err, fs.ErrNotExist) {
		return refuse(c, res, EyeballFile+": "+err.Error(), report)
	}
	if hasDomains {
		s := sample(domains)
		if s != "" {
			s += "\n"
		}
		files = append(files, File{SampleFile, []byte(s)})
	}
	files = append(files, File{ReportFile, lines(report)})
	if err := Commit(c.OutDir, files); err != nil {
		return res, err
	}
	res.Imported = true
	res.Report = report
	return res, nil
}

// refuse writes the report of a refused set: the reason first, then the
// lines of the staged report. The reason names the file and the line. It
// never quotes a staged line.
func refuse(c Config, res Result, why string, report []string) (Result, error) {
	res.Refused = why
	res.IPs, res.Domains = -1, -1
	res.Report = append([]string{"FAIL stage: " + why + "; the lists stay as they were"}, report...)
	if err := WriteReport(c.OutDir, res.Report); err != nil {
		return res, err
	}
	return res, fmt.Errorf("%w: %s", ErrRefused, why)
}

// WriteReport writes the report into outDir. Each line goes through the
// same filter as a staged report, so a line that root makes from an error
// text cannot carry a control byte either.
func WriteReport(outDir string, report []string) error {
	var b bytes.Buffer
	for _, l := range report {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return Commit(outDir, []File{{ReportFile, lines(FilterReport(b.Bytes()))}})
}

// openStage opens the stage directory in stateDir. stateDir itself is the
// state directory of the unit, in /var/lib, which pf-feeds cannot replace.
// The stage directory in it must be a real directory, not a link. The
// result is an os.Root, so no later name can leave the stage.
func openStage(stateDir string) (*os.Root, error) {
	r, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	fi, err := r.Lstat(StageName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNoRun
		}
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s/%s is not a directory", stateDir, StageName)
	}
	return r.OpenRoot(StageName)
}

// readStaged reads one staged file. The file must be a regular file (no
// link, FIFO or device), owned by uid when uid >= 0, and at most max bytes.
// With cut, a larger file gives its first max bytes, and no error. The
// file is read once, through one descriptor, and the caller checks that
// copy. A change to the file after the read has no effect.
func readStaged(r *os.Root, name string, max int64, cut bool, uid int) ([]byte, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	// O_NONBLOCK: if the name became a FIFO after the Lstat, the open
	// does not wait for a writer. The Stat below then refuses it.
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !got.Mode().IsRegular() || !os.SameFile(fi, got) {
		return nil, errors.New("changed while it was opened")
	}
	if uid >= 0 {
		if s, ok := got.Sys().(*syscall.Stat_t); !ok || int(s.Uid) != uid {
			return nil, errors.New("not owned by " + Account)
		}
	}
	if got.Size() > max && !cut {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		if !cut {
			return nil, fmt.Errorf("larger than %d bytes", max)
		}
		b = b[:max]
	}
	return b, nil
}
