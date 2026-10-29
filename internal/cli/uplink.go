package cli

import (
	"fmt"
	"io"

	"pi-fortress/internal/uplink"
)

const uplinkUsage = "usage: pf uplink record -dev IF | watch | show"

// runUplink is the uplink watchdog (internal/uplink). apply runs record
// with WAN_IF. pi-fortress-uplink-watch.timer runs watch. status.sh runs
// show. apply passes each path, so that a test of apply in a fake root
// never writes the paths of the host.
func runUplink(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("uplink", stderr)
	dev := fs.String("dev", "", "record: the uplink device (apply passes WAN_IF)")
	record := fs.String("record", uplink.DefaultRecord, "the record of the uplink connection")
	dir := fs.String("dir", uplink.DefaultDir, "watch, show: the state directory (state and event file)")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	verb, code, ok := verbArgs(fs, stderr, uplinkUsage)
	if !ok {
		return code
	}
	ctx, stop := signalCtx()
	defer stop()
	switch verb {
	case "record":
		if *dev == "" {
			fmt.Fprintln(stderr, "pf uplink record: -dev is required")
			fmt.Fprintln(stderr, uplinkUsage)
			return 2
		}
		r := &uplink.Recorder{Path: *record, Out: stdout}
		if err := r.Record(ctx, *dev); err != nil {
			return fail(stderr, err)
		}
	case "watch":
		w := &uplink.Watcher{Record: *record, Dir: *dir, Out: stdout}
		if err := w.Check(ctx); err != nil {
			fmt.Fprintln(stderr, "uplink:", err)
			return 1
		}
	case "show":
		uplink.Show(*record, *dir, stdout)
	default:
		fmt.Fprintln(stderr, uplinkUsage)
		return 2
	}
	return 0
}
