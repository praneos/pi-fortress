package ship

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func buildBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()
	src := t.TempDir()
	for p, body := range files {
		write(t, filepath.Join(src, p), body)
	}
	var buf bytes.Buffer
	if _, err := Build(&buf, src, BundleOptions{Version: 1}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLintBundlePassesTheGuardedPattern(t *testing.T) {
	raw := buildBundle(t, map[string]string{
		"vm/pi/apply.sh": "" +
			"BROKER_BUDGET=\"-slot-warn-requests=1\"\n" +
			"if [[ -f /etc/pi-fortress/lab ]]; then\n" +
			"  echo \"PF_BROKER_FLAGS=\\\"-lab-echo ${BROKER_BUDGET}\\\"\" >/etc/pi-fortress/broker.env\n" +
			"else\n" +
			"  echo \"PF_BROKER_FLAGS=\\\"${BROKER_BUDGET}\\\"\" >/etc/pi-fortress/broker.env\n" +
			"fi\n",
		"vm/pi/provision.sh": "if [[ \"${PF_LAB:-}\" == 1 ]]; then\n  touch /etc/pi-fortress/lab\nfi\n",
	})
	if err := LintBundle(bytes.NewReader(raw)); err != nil {
		t.Fatalf("guarded pattern should pass: %v", err)
	}
}

func TestLintBundleRefusesAnUnconditionalLabEcho(t *testing.T) {
	raw := buildBundle(t, map[string]string{
		"vm/pi/apply.sh": "echo \"PF_ENGINE_FLAGS=-lab-echo\" >/etc/pi-fortress/engine.env\n",
	})
	if err := LintBundle(bytes.NewReader(raw)); err == nil {
		t.Fatal("an unguarded -lab-echo should refuse")
	}
}

func TestLintBundleRefusesAGuardOnTheWrongCondition(t *testing.T) {
	raw := buildBundle(t, map[string]string{
		"vm/pi/apply.sh": "if [[ \"${DEBUG:-}\" == 1 ]]; then\n  echo \"PF_ENGINE_FLAGS=-lab-echo\" >/etc/pi-fortress/engine.env\nfi\n",
	})
	if err := LintBundle(bytes.NewReader(raw)); err == nil {
		t.Fatal("a guard that does not test the lab marker should refuse")
	}
}

// TestLintPassesTheRealTree ties the lint to the real vm/pi/apply.sh
// and provision.sh, not only the synthetic fixtures above. A change
// that breaks the -lab-echo guard in the real tree fails go test. That
// is the same gate that release.sh runs before it signs a bundle.
func TestLintPassesTheRealTree(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "vm", "pi", "apply.sh")); err != nil {
		t.Skip("not run from inside the module tree")
	}
	var buf bytes.Buffer
	_, err = Build(&buf, root, BundleOptions{
		Version:      1,
		ExcludeNames: []string{".git", ".vagrant"},
		Omit:         []string{"dist", "bin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := LintBundle(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("the real tree fails release-lint: %v", err)
	}
}

// The marker is never a bundle entry (a bundle unpacks under
// /opt/pi-fortress). Thus the path that can install it is a
// shipped script line that creates it.
func TestLintBundleRefusesAnUnguardedMarkerWrite(t *testing.T) {
	for _, line := range []string{
		"touch /etc/pi-fortress/lab",
		": >/etc/pi-fortress/lab",
		"install -m 0644 /dev/null /etc/pi-fortress/lab",
		"[[ -f /etc/pi-fortress/lab ]] || touch /etc/pi-fortress/lab",
	} {
		raw := buildBundle(t, map[string]string{"vm/pi/provision.sh": "set -e\n" + line + "\n"})
		if err := LintBundle(bytes.NewReader(raw)); err == nil {
			t.Errorf("%q with no PF_LAB guard should refuse", line)
		}
	}
}

func TestLintBundleAllowsMarkerTestsAndRemovals(t *testing.T) {
	raw := buildBundle(t, map[string]string{
		"vm/pi/apply.sh":            "if [[ -f /etc/pi-fortress/lab ]]; then\n  echo lab\nfi\n",
		"vm/appliance/firstboot.sh": "rm -f /etc/pi-fortress/lab\n",
		"vm/pi/provision.sh":        "# touch /etc/pi-fortress/lab in the lab only\nif [[ \"${PF_LAB:-}\" == 1 ]]; then\n  touch /etc/pi-fortress/lab\nfi\n",
	})
	if err := LintBundle(bytes.NewReader(raw)); err != nil {
		t.Fatalf("tests, removals and a PF_LAB-guarded touch should pass: %v", err)
	}
}
