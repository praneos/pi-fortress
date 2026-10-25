package admin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const allowMenu = "# candidates\n#crates.io\nexample.com\n\n# considered and rejected\n#evil.example\n"

func TestListEditPreservesComments(t *testing.T) {
	cases := []struct {
		name   string
		list   string
		before string
		remove bool
		value  string
		want   string
		err    error
	}{
		{
			name:   "comments survive an add",
			list:   "house.domains",
			before: "# ads\nads.example\n",
			value:  "tracker.example",
			want:   "# ads\nads.example\ntracker.example\n",
		},
		{
			name:   "comments survive a remove",
			list:   "house.domains",
			before: "# ads\nads.example\ntracker.example\n",
			remove: true,
			value:  "ads.example",
			want:   "# ads\ntracker.example\n",
		},
		{
			name:   "a trailing note block stays trailing",
			list:   "allow.domains",
			before: allowMenu,
			value:  "github.com",
			want:   "# candidates\n#crates.io\nexample.com\ngithub.com\n\n# considered and rejected\n#evil.example\n",
		},
		{
			name:   "a commented-out token is not present",
			list:   "allow.domains",
			before: allowMenu,
			value:  "crates.io",
			want:   "# candidates\n#crates.io\nexample.com\ncrates.io\n\n# considered and rejected\n#evil.example\n",
		},
		{
			name:   "removing a commented-out token touches nothing",
			list:   "allow.domains",
			before: allowMenu,
			remove: true,
			value:  "crates.io",
			want:   allowMenu,
		},
		{
			name:   "an existing token is not added twice",
			list:   "allow.domains",
			before: allowMenu,
			value:  "Example.COM.",
			want:   allowMenu,
		},
		{
			name:   "removing an absent token is a no-op",
			list:   "allow.domains",
			before: allowMenu,
			remove: true,
			value:  "absent.example",
			want:   allowMenu,
		},
		{
			name:   "an invalid token leaves the file alone",
			list:   "allow.domains",
			before: allowMenu,
			value:  "not a domain",
			want:   allowMenu,
			err:    errToken,
		},
		{
			name:   "an unknown list leaves the file alone",
			list:   "house_default.domains",
			before: allowMenu,
			value:  "example.org",
			want:   allowMenu,
			err:    errList,
		},
		{
			name:  "an empty file takes the first token",
			list:  "allow.domains",
			value: "example.com",
			want:  "example.com\n",
		},
		{
			name:   "a file of only comments appends at the end",
			list:   "allow.domains",
			before: "# nothing enabled yet\n\n# see docs\n",
			value:  "example.com",
			want:   "# nothing enabled yet\n\n# see docs\nexample.com\n",
		},
		{
			name:   "a trailing comment on a token line goes with it",
			list:   "allow.domains",
			before: "# head\nexample.com # why\nother.example\n",
			remove: true,
			value:  "example.com",
			want:   "# head\nother.example\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{PolicyDir: t.TempDir()}
			path := filepath.Join(c.PolicyDir, tc.list)
			write(t, path, tc.before)
			var err error
			if tc.remove {
				err = c.ListRemove(tc.list, tc.value)
			} else {
				err = c.ListAdd(tc.list, tc.value)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if string(raw) != tc.want {
				t.Fatalf("got %q, want %q", raw, tc.want)
			}
		})
	}
}

// allow.domains is the forward set of the agent under PARANOID=1. A name
// there also allows all names below it. Thus a leading dot is not a narrower
// entry, and the seat refuses it and does not write the bare name. The
// other domain lists read ".name" as "name".
func TestAllowDomainsRefusesLeadingDot(t *testing.T) {
	if got, err := ValidateToken("allow.domains", ".example.com"); !errors.Is(err, errToken) || !strings.Contains(err.Error(), "leading dot") {
		t.Fatalf("ValidateToken(allow.domains, .example.com) = %q, %v; want a refusal that names the dot", got, err)
	}
	if got, err := ValidateToken("allow.domains", "*.example.com"); err != nil || got != "example.com" {
		t.Fatalf("ValidateToken(allow.domains, *.example.com) = %q, %v", got, err)
	}
	for _, list := range []string{"blacklist.domains", "never_block.domains", "house.domains"} {
		if got, err := ValidateToken(list, ".ads.example"); err != nil || got != "ads.example" {
			t.Errorf("ValidateToken(%s, .ads.example) = %q, %v", list, got, err)
		}
	}
	c := &Config{PolicyDir: t.TempDir()}
	path := filepath.Join(c.PolicyDir, "allow.domains")
	write(t, path, allowMenu)
	if err := c.ListAdd("allow.domains", ".example.org"); !errors.Is(err, errToken) {
		t.Fatalf("ListAdd = %v, want errToken", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != allowMenu {
		t.Fatalf("file changed: %q", raw)
	}
}
