package enroll

import (
	"os"
	"testing"
)

// The default directories of the paste file are those of the host. No
// test here intends to write into them. A test that does finds the root
// directory on a desktop seat, and fails for a reason unrelated to the test.
func TestMain(m *testing.M) {
	labPolicyDir = "/nonexistent/pf-enroll-test/lab"
	gatewayDir = "/nonexistent/pf-enroll-test/etc"
	brokerState = func() string { return "" }
	os.Exit(m.Run())
}
