package ship

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckSigners(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest"
	const dist = "pi-fortress-dist"
	cases := []struct {
		name, ns, body string
		want           string // "" is accepted; else a part of the error
	}{
		{"ship line", Namespace, `release namespaces="pi-fortress-release" ` + key + "\n", ""},
		{"dist line", dist, `release@pi-fortress namespaces="pi-fortress-dist" ` + key + "\n", ""},
		{"comment, blank and two keys", dist, "# rotated\n\nrelease@pi-fortress namespaces=\"pi-fortress-dist\" " + key + " old\n  release@pi-fortress namespaces=\"pi-fortress-dist\" " + key + "\n", ""},
		{"other options kept", Namespace, `release cert-authority,namespaces="pi-fortress-release",valid-after="20260101" ` + key + "\n", ""},
		{"no last line break", Namespace, `release namespaces="pi-fortress-release" ` + key, ""},
		{"no namespaces", Namespace, "release " + key + "\n", "has no namespaces= option"},
		{"no namespaces, other option", Namespace, `release valid-after="20260101" ` + key + "\n", "has no namespaces= option"},
		{"no namespaces on the second line", dist, `release@pi-fortress namespaces="pi-fortress-dist" ` + key + "\nrelease@pi-fortress " + key + "\n", "line 2 has no namespaces="},
		{"ship namespace in the dist file", dist, `release@pi-fortress namespaces="pi-fortress-release" ` + key + "\n", `needs namespaces="pi-fortress-dist" only`},
		{"dist namespace in the ship file", Namespace, `release namespaces="pi-fortress-dist" ` + key + "\n", `needs namespaces="pi-fortress-release" only`},
		{"both namespaces", Namespace, `release namespaces="pi-fortress-release,pi-fortress-dist" ` + key + "\n", "only"},
		{"pattern", Namespace, `release namespaces="*" ` + key + "\n", "only"},
		{"two namespaces options", Namespace, `release namespaces="pi-fortress-release",NAMESPACES="pi-fortress-dist" ` + key + "\n", "only"},
		{"namespaces in the principal only", Namespace, `namespaces="pi-fortress-release" ` + key + "\n", "has no namespaces= option"},
		{"no key line", Namespace, "# empty\n\n", "holds no key line"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "signers")
			write(t, p, c.body)
			err := CheckSigners(p, c.ns)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused a correct file: %v", err)
			case c.want != "" && err == nil:
				t.Fatalf("accepted %q for namespace %s", c.body, c.ns)
			case c.want != "" && (!strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), p)):
				t.Fatalf("error %q does not name the file and say %q", err, c.want)
			}
		})
	}
}

// A line with no namespaces option is refused before ssh-keygen runs, so a
// bundle that the key signed correctly is still refused, and nothing is
// applied.
func TestInstallRefusesSignerLineWithNoNamespaces(t *testing.T) {
	r := newRig(t, true)
	pub := strings.Fields(read(t, r.key+".pub"))
	write(t, r.in.Signers, Principal+" "+pub[0]+" "+pub[1]+"\n")
	r.ship(200, r.key)
	row, ok := r.in.Run()
	if !ok || row.Result != "bad_sig" || !strings.Contains(row.Reason, "namespaces=") {
		t.Fatalf("expected bad_sig naming namespaces=, got %+v", row)
	}
	if r.applies != 0 {
		t.Fatal("apply ran on a refused bundle")
	}
	r.untouched()
}
