package cli

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// Version is set by make release through -ldflags -X.
var Version = "dev"

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "pf %s %s/%s %s\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	var rev, at, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			at = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if rev != "" {
		fmt.Fprintf(w, "commit %s %s modified=%s\n", rev, at, modified)
	}
}
