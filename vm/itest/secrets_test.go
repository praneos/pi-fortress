//go:build vagrant

package itest

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func secretsTests(t *testing.T) {
	if !hasCoreEcho(t) {
		t.Skip("no pf-core-echo.test on this gateway: installCoreEcho could not lend it one")
	}
	const (
		slotGH = "a1b2c3d4e5f67890"
		slotA  = "b0b1b2b3b4b5b6b7"
		slotB  = "c0c1c2c3c4c5c6c7"
	)
	phGH := "pf_" + slotGH + "_GITHUB_TOKEN"
	phOatA := "pf_" + slotA + "_CLAUDE_OAT"
	phOrtA := "pf_" + slotA + "_CLAUDE_ORT"
	phOatB := "pf_" + slotB + "_CLAUDE_OAT"
	oatA := "sk-ant-oat01-" + strings.Repeat("A", 64)
	oatB := "sk-ant-oat01-" + strings.Repeat("C", 64)
	oatNew := "sk-ant-oat01-" + strings.Repeat("N", 64)
	ortNew := "sk-ant-ort01-" + strings.Repeat("R", 64)

	seedLabSecrets(t)
	t.Cleanup(func() {
		restoreLabSecrets(t)
	})
	time.Sleep(time.Second)

	core := func(auth string) string {
		t.Helper()
		out, _ := ssh(t, 15*time.Second, "agent", "curl -sS --connect-timeout 4 --max-time 8 -H 'Authorization: Bearer "+auth+"' https://pf-core-echo.test/")
		return out
	}
	open := func(auth string) string {
		t.Helper()
		out, _ := ssh(t, 15*time.Second, "agent", "curl -sS --connect-timeout 4 --max-time 8 -H 'Authorization: Bearer "+auth+"' https://pf-open-echo.test/")
		return out
	}

	t.Run("core echo substitutes placeholder", func(t *testing.T) {
		body := core(phGH)
		if !contains(body, "lab_fence_github") || !contains(body, `"substituted": true`) {
			t.Fatal(body)
		}
	})
	for _, tc := range []struct{ slot, ph, want, other string }{
		{"A", phOatA, oatA, oatB},
		{"B", phOatB, oatB, oatA},
	} {
		t.Run("core echo substitutes slot "+tc.slot+" oat only", func(t *testing.T) {
			body := core(tc.ph)
			if !contains(body, tc.want) || contains(body, tc.other) || contains(body, tc.ph) {
				t.Fatal(body)
			}
		})
	}
	t.Run("unslotted placeholder is not substituted", func(t *testing.T) {
		body := core("pf_CLAUDE_OAT")
		if !contains(body, "pf_CLAUDE_OAT") || contains(body, oatA) || contains(body, oatB) {
			t.Fatal(body)
		}
	})
	// A placeholder aimed at a host its kind may not reach is refused
	// (docs/fence.md, kind_not_allowed_for_sni), never forwarded.
	t.Run("non-core refuses placeholder", func(t *testing.T) {
		body := open(phGH)
		if !contains(body, "this request could not be completed") || contains(body, "lab_fence_github") {
			t.Fatal(body)
		}
	})
	t.Run("non-core refuses oat placeholder", func(t *testing.T) {
		body := open(phOatA)
		if !contains(body, "this request could not be completed") || contains(body, oatA) {
			t.Fatal(body)
		}
	})
	t.Run("non-core strips live-looking token", func(t *testing.T) {
		body := open("lab_fence_github")
		if !contains(body, `"stripped": true`) || contains(body, "lab_fence_github") {
			t.Fatal(body)
		}
	})
	t.Run("non-core strips live oat", func(t *testing.T) {
		body := open(oatA)
		if !contains(body, `"stripped": true`) || contains(body, oatA) {
			t.Fatal(body)
		}
	})
	// A field name cannot be rewritten, so a key there is refused on each
	// host (docs/fence.md, key_in_header_name).
	for _, name := range []string{"X-lab_fence_github", "X-" + phGH} {
		t.Run("header name refused: "+name[:8], func(t *testing.T) {
			for _, host := range []string{"pf-open-echo.test", "pf-core-echo.test"} {
				body, _ := ssh(t, 15*time.Second, "agent", "curl -sS --connect-timeout 4 --max-time 8 -H '"+name+": 1' https://"+host+"/")
				if !contains(body, "this request could not be completed") || contains(body, "lab_fence_github") {
					t.Fatal(host, body)
				}
			}
		})
	}
	t.Run("oauth refresh harvests into that slot", func(t *testing.T) {
		body, _ := ssh(t, 15*time.Second, "agent", `curl -sS --connect-timeout 4 --max-time 8 -H 'Content-Type: application/json' --data-raw '{"grant_type":"refresh_token","refresh_token":"`+phOrtA+`"}' https://pf-core-echo.test/v1/oauth/token`)
		if !contains(body, phOatA) || !contains(body, phOrtA) || contains(body, phOatB) || contains(body, oatNew) || contains(body, ortNew) {
			t.Fatal(body)
		}
		env := pi(t, "sudo cat /etc/pi-fortress/broker/secrets.env")
		if !contains(env, slotA+"_CLAUDE_OAT="+oatNew) || !contains(env, slotA+"_CLAUDE_ORT="+ortNew) || !contains(env, slotB+"_CLAUDE_OAT="+oatB) {
			t.Fatal(env)
		}
	})
	// The frame path, end to end (docs/fence.md 5.3c). The core echo is
	// the only origin server in any tier that upgrades. Thus this is the
	// one run in which a frame crosses the fence and can be read back on
	// the far side. All other websocket checks are unit tests on the legs
	// of the broker. The strip log is the second half: a scrubbed frame
	// that comes back shows that the rewrite occurred. The row shows that
	// the operator got the notice.
	t.Run("a websocket frame is scrubbed on its way out", func(t *testing.T) {
		live := "ghp_" + strings.Repeat("a", 36)
		const row = `'"where":"ws","rule":"github_classic"'`
		before := grepCount(t, "/var/log/pi-fortress/strip.jsonl", row)
		got := wsEcho(t, "pf-core-echo.test", "/ws", "frame "+live+" end")
		if len(got) != 1 || got[0] != "frame pf_stripped end" {
			t.Fatalf("the fixture reflected %q", got)
		}
		if after := grepCount(t, "/var/log/pi-fortress/strip.jsonl", row); after <= before {
			t.Fatalf("the frame was scrubbed and no row said so: %d -> %d", before, after)
		}
	})
	// The per-slot hourly budget (docs/fence.md 5.2d). This run shows that
	// the fence counts what it substituted. It also shows that the socket
	// through which the Secrets screen reads the count answers on a real
	// box. No unit test sees that half. The run does not make a threshold
	// fire. The thresholds are start-time flags: to fire one, apply a
	// different net.env and restart the broker. That is a box-wide change
	// that this group must not make around the other agents. The unit
	// tests and a hardware check on a real Pi prove the warn row itself.
	t.Run("the hourly budget counts what the fence substituted", func(t *testing.T) {
		before := slotHour(t, slotGH)
		if body := core(phGH); !contains(body, "lab_fence_github") {
			t.Fatal(body)
		}
		after := slotHour(t, slotGH)
		if after <= before {
			t.Fatalf("the slot's hour went %d -> %d across one substituted request", before, after)
		}
	})
}

// slotHour asks the admin socket of the broker what one slot spent in the
// last hour. The window is in the memory of that process, so there is
// nothing on disk to read. python3 is on the box from provision.sh, and
// the socket is root-only by design.
func slotHour(t *testing.T, slot string) int {
	t.Helper()
	out := pi(t, "sudo -n python3 - <<'PY'\n"+
		"import socket\n"+
		"s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"+
		"s.settimeout(10)\n"+
		"s.connect('/run/pi-fortress/broker/admin.sock')\n"+
		"s.sendall(b'BUDGET\\n')\n"+
		"print(s.recv(65536).decode().strip())\n"+
		"PY")
	f := strings.Fields(out)
	if len(f) > 0 && f[0] == "err" {
		t.Fatalf("the broker refused BUDGET: %s", out)
	}
	for i := 0; i+2 < len(f); i += 3 {
		if f[i] != slot {
			continue
		}
		n, err := strconv.Atoi(f[i+1])
		if err != nil {
			t.Fatalf("the budget line is not slot/requests/bytes: %q", out)
		}
		return n
	}
	return 0
}
