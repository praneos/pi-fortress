package doctor

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"pi-fortress/internal/render"
)

// SegmentParanoid is one rung per plain segment armed PARANOID=on. Its
// allow.<name>.domains must be there, readable by pf dns, and must hold a
// usable name: render refuses an apply on this check. It is a FAIL, not a
// warning, because the box is one restart from a real problem. pf dns
// will not start on a paranoid segment whose file is gone, and the DNS of
// each segment goes with it. Unarmed segments say nothing. A box with no
// segments.d has no rung.
func SegmentParanoid(segmentsDir string) []Result {
	files, err := filepath.Glob(filepath.Join(segmentsDir, "*.env"))
	if err != nil {
		return nil
	}
	sort.Strings(files)
	var rs []Result
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".env")
		at := func(detail string, st Status) Result {
			return Result{Rung: "paranoid", Where: name, Detail: detail, Status: st}
		}
		armed := ""
		err := render.EnvLines(file, func(_ int, key, val string) error {
			if key == "PARANOID" {
				armed = val
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			rs = append(rs, at(fmt.Sprintf("%s cannot be read: %v", file, err), Fail))
			continue
		}
		if armed != "on" {
			continue
		}
		allow := render.SegmentAllowPath(segmentsDir, name)
		n, err := render.CheckSegmentAllow(allow)
		if err != nil {
			rs = append(rs, at(fmt.Sprintf("PARANOID=on, but %v; the next apply refuses and pf dns will not start on it. Fill the file or set PARANOID=off in %s", err, file), Fail))
			continue
		}
		rs = append(rs, at(fmt.Sprintf("on: %d name(s) in %s", n, allow), OK))
	}
	return rs
}
