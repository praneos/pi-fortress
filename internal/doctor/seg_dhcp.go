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

// SegmentDHCP is the dhcp rung of the house, for each plain segment with
// DHCP=on. Its own dnsmasq instance must be active. While it is active,
// the lease count follows, as it does for the house. A dead instance is a
// FAIL: each device on that segment that cannot take a static address is
// offline until the instance comes back. Segments without DHCP say
// nothing, and a box with no segments.d has no rung.
func SegmentDHCP(segmentsDir string) []Result {
	files, err := filepath.Glob(filepath.Join(segmentsDir, "*.env"))
	if err != nil {
		return nil
	}
	sort.Strings(files)
	var rs []Result
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".env")
		at := func(rung, detail string, st Status) Result {
			return Result{Rung: rung, Where: name, Detail: detail, Status: st}
		}
		dhcp := ""
		err := render.EnvLines(file, func(_ int, key, val string) error {
			if key == "DHCP" {
				dhcp = val
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			rs = append(rs, at("dhcp", fmt.Sprintf("%s cannot be read: %v", file, err), Fail))
			continue
		}
		if dhcp != "on" {
			continue
		}
		unit := render.SegmentDHCPUnit(name)
		if !unitActive(unit) {
			rs = append(rs, at("dhcp", unit+" is not active; journalctl -u "+unit, Fail))
			continue
		}
		rs = append(rs, at("dhcp", unit+" active", OK))
		rs = append(rs, Segment{Name: name, Leases: render.SegmentLeases(name)}.leaseRung(at))
	}
	return rs
}
