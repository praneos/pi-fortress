//go:build vagrant

package itest

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	deskSegFile    = "/etc/pi-fortress/segments.d/desk.env"
	deskSegBackup  = "/var/lib/pi-fortress/itest-desk.env"
	deskSetupCopy  = "/tmp/pf-itest-desk-setup.sh"
	deskCAOnDesk   = "/tmp/pf-itest-desk-ca.pem"
	engineCertPath = "/var/lib/pi-fortress/engine/ca-cert.pem"
)

// deskInspectTests arm INSPECT=on on the desk segment for the length of
// the group, then put the segment file back and apply again. A real desk
// is off by default, and the desk group before this one tests that state.
// The backup stays under /var/lib until the restore is done. Thus a run
// that crashed between the two leaves the next run a file to restore from.
func deskInspectTests(t *testing.T) {
	needHost(t, "desk")
	if !hasCoreEcho(t) {
		t.Skip("no pf-core-echo.test on this gateway")
	}
	e := netenv(t)
	gw, self := e["DESK_IP"], e["DESK_SEAT_IP"]
	const (
		slotGH = "a1b2c3d4e5f67890"
		slotA  = "b0b1b2b3b4b5b6b7"
	)
	phGH := "pf_" + slotGH + "_GITHUB_TOKEN"
	phOatA := "pf_" + slotA + "_CLAUDE_OAT"
	oatA := "sk-ant-oat01-" + strings.Repeat("A", 64)

	arm := strings.Join([]string{
		"set -e",
		"[ -e " + deskSegBackup + " ] || cp -p " + deskSegFile + " " + deskSegBackup,
		"grep -v '^INSPECT=' " + deskSegBackup + " > " + deskSegFile,
		"echo INSPECT=on >> " + deskSegFile,
	}, "; ")
	pi(t, "sudo sh -c "+shellQuote(arm))
	t.Cleanup(func() { disarmDeskInspect(t, gw) })
	if out, err := ssh(t, 5*time.Minute, "pi", "sudo /usr/local/sbin/pf apply --local"); err != nil {
		t.Fatalf("pf apply --local with INSPECT=on: %v\n%s", err, out)
	}
	ca := pi(t, "sudo cat "+engineCertPath)
	deskSetup(t, "printf %s "+base64.StdEncoding.EncodeToString([]byte(ca))+" | base64 -d > "+deskCAOnDesk, "ca "+deskCAOnDesk)
	t.Cleanup(func() {
		if out, err := ssh(t, 45*time.Second, "desk", "sudo bash "+deskSetupCopy+" ca-remove; rm -f "+deskSetupCopy+" "+deskCAOnDesk); err != nil {
			t.Errorf("setup.sh ca-remove on the desk: %v\n%s", err, out)
		}
	})
	// The echo names resolve on the desk and open their addresses in the
	// gate of the desk for two hours. The desk group asserts that an
	// address that the desk never resolved is dropped, so the next run
	// must find them closed.
	t.Cleanup(func() {
		set := "resolved_desk_v4"
		for _, ip := range []string{e["ECHO_CORE_IP"], e["ECHO_OPEN_IP"]} {
			_, _ = ssh(t, 15*time.Second, "pi", "sudo nft delete element inet fortress "+set+" { "+ip+" } 2>/dev/null || true")
		}
	})
	seedLabSecrets(t)
	t.Cleanup(func() { restoreLabSecrets(t) })
	time.Sleep(time.Second)

	t.Run("the engine listens on the desk address", func(t *testing.T) {
		eventually(t, 20*time.Second, func() string {
			if out, _ := ssh(t, 15*time.Second, "pi", "sudo ss -ltn"); !contains(out, " "+gw+":8080 ") {
				return "nothing listens on " + gw + ":8080:\n" + out
			}
			return ""
		})
		if env := pi(t, "cat /etc/pi-fortress/engine.env /etc/pi-fortress/broker.env"); !contains(env, "-inspect-listen "+gw+":8080") || !contains(env, "-fence-net "+e["DESK_NET"]) {
			t.Fatalf("the daemons do not serve the desk:\n%s", env)
		}
		addrs := pi(t, "ip -br -4 addr")
		deskIf := devWith(addrs, gw)
		if out := pi(t, "sudo nft list ruleset"); !contains(out, `iifname "`+deskIf+`" tcp dport 443 redirect to :8080`) {
			t.Fatalf("no 443 redirect on %s", deskIf)
		}
	})
	desk := func(args string) string {
		t.Helper()
		out, _ := ssh(t, 20*time.Second, "desk", "bash -lc "+shellQuote("curl -4 -sS --connect-timeout 4 --max-time 12 "+args))
		return out
	}
	t.Run("HTTPS of the desk goes through the engine", func(t *testing.T) {
		code := strings.TrimSpace(desk("-o /dev/null -w '%{http_code}' https://" + e["ALLOW_DOMAIN"]))
		if !curlOK(code) {
			t.Fatalf("https://%s through the fence: %q", e["ALLOW_DOMAIN"], code)
		}
		if out := desk("-v -o /dev/null https://" + e["ALLOW_DOMAIN"] + " 2>&1"); !contains(out, "issuer: CN=pi-fortress") {
			t.Fatalf("the leaf is not from the engine:\n%s", out)
		}
	})
	// The system store covers Go, curl and git. Python requests reads
	// certifi unless the environment of setup.sh ca names the system
	// bundle, and the standard library ssl module reads the system bundle.
	// A login shell, because that is where /etc/profile.d applies.
	t.Run("Python trusts the engine on the desk", func(t *testing.T) {
		url := "https://" + e["ALLOW_DOMAIN"] + "/"
		for name, code := range map[string]string{
			"urllib":   "import urllib.request; print(urllib.request.urlopen('" + url + "', timeout=10).status)",
			"requests": "import requests; print(requests.get('" + url + "', timeout=10).status_code)",
		} {
			out, err := ssh(t, 30*time.Second, "desk", "bash -lc "+shellQuote("python3 -c "+shellQuote(code)))
			if name == "requests" && contains(out, "No module named") {
				t.Logf("no requests module on the desk: %s not tested", name)
				continue
			}
			if err != nil || !curlOK(strings.TrimSpace(out)) {
				t.Errorf("%s through the fence: %v\n%s", name, err, out)
			}
		}
	})
	t.Run("Firefox gets the CA by policy", func(t *testing.T) {
		if out := mustSSH(t, "desk", "cat /etc/firefox/policies/policies.json"); !contains(out, `"Install": ["/etc/pi-fortress/desk-ca.pem"]`) {
			t.Fatal(out)
		}
	})
	t.Run("core echo substitutes a desk placeholder", func(t *testing.T) {
		body := desk("-H 'Authorization: Bearer " + phGH + "' https://pf-core-echo.test/")
		if !contains(body, "lab_fence_github") || !contains(body, `"substituted": true`) {
			t.Fatal(body)
		}
	})
	t.Run("non-core refuses a desk placeholder", func(t *testing.T) {
		body := desk("-H 'Authorization: Bearer " + phOatA + "' https://pf-open-echo.test/")
		if !contains(body, "this request could not be completed") || contains(body, oatA) {
			t.Fatal(body)
		}
	})
	t.Run("non-core strips a live key from the desk", func(t *testing.T) {
		body := desk("-H 'Authorization: Bearer lab_fence_github' https://pf-open-echo.test/")
		if !contains(body, `"stripped": true`) || contains(body, "lab_fence_github") {
			t.Fatal(body)
		}
		eventually(t, 15*time.Second, func() string {
			rows, _ := ssh(t, 15*time.Second, "pi", "sudo tail -n 50 /var/log/pi-fortress/strip.jsonl")
			if lineWith(rows, `"host":"pf-open-echo.test"`, `"client_ip":"`+self+`"`) {
				return ""
			}
			return "no strip row for the desk:\n" + rows
		})
	})
	t.Run("header-name key from the desk refused", func(t *testing.T) {
		body := desk("-H 'X-" + phGH + ": 1' https://pf-open-echo.test/")
		if !contains(body, "this request could not be completed") {
			t.Fatal(body)
		}
	})
	t.Run("the agent fence still substitutes", func(t *testing.T) {
		out, _ := ssh(t, 15*time.Second, "agent", "curl -sS --connect-timeout 4 --max-time 8 -H 'Authorization: Bearer "+phGH+"' https://pf-core-echo.test/")
		if !contains(out, "lab_fence_github") {
			t.Fatal(out)
		}
	})
	t.Run("INSPECT=off gives the desk raw TLS again", func(t *testing.T) {
		disarmDeskInspect(t, gw)
		if out := desk("-v -o /dev/null https://" + e["ALLOW_DOMAIN"] + " 2>&1"); contains(out, "issuer: CN=pi-fortress") || !contains(out, "issuer:") {
			t.Fatalf("the desk still gets a leaf of the engine, or no TLS at all:\n%s", out)
		}
		if out, _ := ssh(t, 15*time.Second, "pi", "sudo ss -ltn"); contains(out, " "+gw+":8080 ") {
			t.Fatalf("the engine still listens on %s:8080:\n%s", gw, out)
		}
	})
}

// disarmDeskInspect puts the segment file back and applies. A second call
// finds no backup and does nothing.
func disarmDeskInspect(t *testing.T, gw string) {
	t.Helper()
	out, err := ssh(t, 15*time.Second, "pi", "sudo sh -c "+shellQuote("set -e; [ -e "+deskSegBackup+" ] || exit 0; cat "+deskSegBackup+" > "+deskSegFile+"; cmp -s "+deskSegBackup+" "+deskSegFile+"; rm -f "+deskSegBackup+"; echo restored"))
	if err != nil {
		t.Errorf("the desk segment file was not restored from %s: %v\n%s", deskSegBackup, err, out)
		return
	}
	if !contains(out, "restored") {
		return
	}
	if out, err := ssh(t, 5*time.Minute, "pi", "sudo /usr/local/sbin/pf apply --local"); err != nil {
		t.Errorf("pf apply --local after the desk restore: %v\n%s", err, out)
	}
	if env, _ := ssh(t, 15*time.Second, "pi", "cat /etc/pi-fortress/engine.env"); contains(env, "-inspect-listen "+gw) {
		t.Errorf("engine.env still has the desk after the restore:\n%s", env)
	}
}

// deskSetup copies vm/desk/setup.sh of this tree to the desk and runs one
// command of it as root. The repo copy on the desk is from the last
// provision, so it can be older than the code under test. pre runs first,
// as the ssh user.
func deskSetup(t *testing.T, pre, args string) string {
	t.Helper()
	src, err := os.ReadFile("../desk/setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	if _, err := w.Write(src); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := "set -e; printf %s " + base64.StdEncoding.EncodeToString(z.Bytes()) + " | base64 -d | gunzip > " + deskSetupCopy + "; " + pre + "; sudo bash " + deskSetupCopy + " " + args
	out, err := ssh(t, 60*time.Second, "desk", "bash -c "+shellQuote(cmd))
	if err != nil {
		t.Fatalf("setup.sh %s on the desk: %v\n%s", args, err, out)
	}
	return out
}
