package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"pi-fortress/internal/monitor"
)

const monitorUsage = "usage: pf monitor once|run|show|avg [-n rows] [-since 24h] [-interval s]"

func runMonitor(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("monitor", stderr)
	interval := fs.Int("interval", 300, "run loop seconds")
	dir := fs.String("dir", "", "log directory (system-<day>.jsonl, procs-<day>.jsonl)")
	n := fs.Int("n", 10, "rows for show")
	since := fs.Duration("since", 24*time.Hour, "window for avg")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	verb, code, ok := verbArgs(fs, stderr, monitorUsage)
	if !ok {
		return code
	}
	m := monitor.Defaults()
	m.Interval = time.Duration(*interval) * time.Second
	if *dir != "" {
		m.Dir = *dir
	}
	ctx, stop := signalCtx()
	defer stop()
	switch verb {
	case "once":
		m.Sample()
		time.Sleep(time.Second)
		monitor.Print(stdout, []monitor.Sample{m.Sample()})
	case "run":
		if err := m.Run(ctx); err != nil {
			return fail(stderr, err)
		}
	case "show":
		rows, err := m.Tail(*n)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintln(stderr, "monitor: no log yet in", m.Dir)
				return 1
			}
			return fail(stderr, err)
		}
		monitor.Print(stdout, rows)
	case "avg":
		sum, err := m.Summarize(time.Now().Add(-*since))
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(stderr, "monitor: no samples in the last %s in %s\n", *since, m.Dir)
				return 1
			}
			return fail(stderr, err)
		}
		monitor.PrintSummary(stdout, sum)
	default:
		fmt.Fprintln(stderr, monitorUsage)
		return 2
	}
	return 0
}
