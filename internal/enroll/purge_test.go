package enroll

import (
	"testing"
	"time"
)

// The retention argument decides which quarantined slots are deleted
// permanently. So each way to say something that it did not mean must be
// a refusal. Sscanf stopped at the first non-digit and reported no error,
// so "7x" was seven days. The day multiplication could overflow into a
// negative duration. And the non-day path never checked the sign, so
// "-1h" put the cutoff in the future and purged the full quarantine.
func TestParseDaysRefusesWhatItCannotMean(t *testing.T) {
	for _, bad := range []string{
		"7x", "7 d", "", "d", "-1d", "-1h", "0x10d", "+d",
		"1000000000000000000d", "9223372036854775807d", "seven",
	} {
		if d, err := parseDays(bad); err == nil {
			t.Errorf("parseDays(%q) = %v, want an error", bad, d)
		}
	}
	for _, c := range []struct {
		in   string
		want time.Duration
	}{
		{"7d", 7 * 24 * time.Hour},
		{"0d", 0},
		{"1h", time.Hour},
		{"90m", 90 * time.Minute},
	} {
		got, err := parseDays(c.in)
		if err != nil || got != c.want {
			t.Errorf("parseDays(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
}
