//go:build vagrant

package itest

import "testing"

func TestLab(t *testing.T) {
	requireLab(t)
	// Before all groups. The fixture that the secrets and enroll groups
	// read is a marker file and a policy line. A real Pi under
	// PF_E2E_DESTRUCTIVE=1 borrows both for the run. Its teardown is on
	// this t, so it runs last.
	installCoreEcho(t)
	runGroup(t, "policy", policyTests)
	runGroup(t, "drops", dropTests)
	runGroup(t, "fakeip", fakeIPTests)
	runGroup(t, "eyeball", labOnly(eyeballTests))
	runGroup(t, "strip", labOnly(stripTests))
	runGroup(t, "secrets", labOnly(secretsTests))
	runGroup(t, "setup", labOnly(setupTests))
	runGroup(t, "agent-vm", agentVMTests)
	runGroup(t, "enroll", labOnly(enrollTests))
	runGroup(t, "dns-segments", dnsSegmentTests)
	runGroup(t, "house", houseTests)
	runGroup(t, "house-devices", houseDeviceTests)
	runGroup(t, "seg-dhcp", labOnly(segDHCPTests))
	runGroup(t, "desk", deskTests)
	runGroup(t, "desk-inspect", labOnly(deskInspectTests))
	runGroup(t, "ntp", labOnly(ntpTests))
	// Opt-in: PF_E2E_FUZZ_NTP=1, a lab gateway only.
	runGroup(t, "ntp-fuzz", ntpFuzzOptIn(ntpFuzzTests))
	runGroup(t, "uplink", uplinkTests)
	// Last: with PF_E2E_REBOOT=1 it reboots the Pi.
	runGroup(t, "tui", labOnly(tuiTests))
	runGroup(t, "ops", opsTests)
	// Very last: it ships bundles and does a rollback of the gateway,
	// PF_E2E_LIFECYCLE=1 only (docs/signed_ship.md).
	runGroup(t, "lifecycle", lifecycleOptIn(lifecycleTests))
}
