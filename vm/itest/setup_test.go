//go:build vagrant

package itest

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

var reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// wwwSHA256 is the sha256 of a file that www serves. It is read from the
// Pi as getting_started §2 tells the operator, never from the agent.
func wwwSHA256(t *testing.T, name string) string {
	t.Helper()
	f := strings.Fields(pi(t, "sudo sha256sum /var/lib/pi-fortress/www/"+name))
	if len(f) == 0 || !reSHA256.MatchString(f[0]) {
		t.Fatalf("no sha256 for www/%s on the Pi: %v", name, f)
	}
	return f[0]
}

// enrollCmd enrolls the agent with setup.sh: the repo copy where the lab
// mounts it, or else the Pi copy over curl, as an operator would.
func enrollCmd(ca string) string {
	return "if [ -f /vagrant/vm/agent/setup.sh ]; then sudo bash /vagrant/vm/agent/setup.sh 10.77.0.1 " + ca +
		"; else curl -fsS --max-time 10 http://10.77.0.1/setup.sh | sudo bash -s -- 10.77.0.1 " + ca + "; fi"
}

func setupTests(t *testing.T) {
	t.Run("setup.sh served on Pi:80", func(t *testing.T) {
		out := agent(t, "curl -fsS --max-time 5 http://10.77.0.1/setup.sh")
		if !contains(out, "pi-fortress setup") {
			t.Fatal(out)
		}
	})
	t.Run("ca.pem served on Pi:80", func(t *testing.T) {
		out := agent(t, "curl -fsS --max-time 5 http://10.77.0.1/ca.pem")
		if !contains(out, "BEGIN CERTIFICATE") {
			t.Fatal(out)
		}
	})
	t.Run("setup.sh enroll + inspect", func(t *testing.T) {
		ca := wwwSHA256(t, "ca.pem")
		out, err := ssh(t, 90*time.Second, "agent", enrollCmd(ca))
		if err != nil {
			logs, _ := ssh(t, 15*time.Second, "pi", "sudo journalctl -u pi-fortress-broker -u pi-fortress-engine -n 80 --no-pager")
			t.Fatalf("%v\n%s\n-- journal --\n%s", err, out, logs)
		}
		if _, err := ssh(t, 20*time.Second, "agent", "curl -4 -fsS --max-time 15 --http1.1 --cacert /etc/pi-fortress/egress-ca.pem -o /dev/null https://pf-open-echo.test/"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("HTTPS fails without CA", func(t *testing.T) {
		// Registered before the CA is removed. Thus the agent is enrolled
		// again if the check below passes, fails or dies: each group
		// after this one needs the agent to trust the Pi.
		ca := wwwSHA256(t, "ca.pem")
		t.Cleanup(func() {
			if out, err := ssh(t, 90*time.Second, "agent", enrollCmd(ca)); err != nil {
				t.Errorf("re-enroll after CA delete: %v\n%s", err, out)
			}
		})
		_, _ = ssh(t, 20*time.Second, "agent", "sudo rm -f /usr/local/share/ca-certificates/pi-fortress-egress.crt /usr/local/share/ca-certificates/pi-fortress-mitm.crt /etc/pi-fortress/egress-ca.pem /etc/pi-fortress/mitm-ca.pem; sudo update-ca-certificates >/dev/null")
		_, err := ssh(t, 15*time.Second, "agent", "curl -fsS --max-time 10 -o /dev/null https://example.com/")
		if err == nil {
			t.Fatal("https succeeded without CA")
		}
	})
	t.Run("setup.sh refuses a CA with no sha256", func(t *testing.T) {
		out, err := ssh(t, 30*time.Second, "agent", "sudo bash /vagrant/vm/agent/setup.sh 10.77.0.1")
		// The refusal is on stderr, which ssh folds into err.
		if err == nil || !contains(err.Error()+out, "sha256 is required") {
			t.Fatalf("%v\n%s", err, out)
		}
	})
}
