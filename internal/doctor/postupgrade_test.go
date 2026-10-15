package doctor

import (
	"errors"
	"io"
	"testing"
	"time"
)

func find(t *testing.T, rs []Result, rung, where string) Result {
	t.Helper()
	for _, r := range rs {
		if r.Rung == rung && r.Where == where {
			return r
		}
	}
	t.Fatalf("no %s/%s rung in %+v", rung, where, rs)
	return Result{}
}

func TestPostUpgradeAllGreen(t *testing.T) {
	cfg := PostUpgradeConfig{
		Units:        []string{"pi-fortress-broker.service", "pi-fortress-engine.service"},
		Segments:     []Segment{{Name: "agent", IP: "10.77.0.1"}, {Name: "house", IP: "10.78.0.1"}},
		BlockDomain:  "pi-fortress-block.test",
		PublicDomain: "example.com",
		BrokerSocket: "/run/pi-fortress/broker/broker.sock",
		EngineAddr:   "10.77.0.1:8080",
		UplinkServer: "9.9.9.9",
		UplinkName:   "example.com",
		Timeout:      time.Second,
		UnitActive:   func(string) bool { return true },
		Resolve: func(server, name string, _ time.Duration) ([]string, error) {
			if name == "pi-fortress-block.test" {
				return []string{"0.0.0.0"}, nil
			}
			return []string{"93.184.216.34"}, nil
		},
		DialUnix: func(string, time.Duration) error { return nil },
		DialTCP:  func(string, time.Duration) error { return nil },
	}
	rs := PostUpgrade(cfg)
	if code := Report(io.Discard, rs); code != 0 {
		t.Fatalf("code %d over %+v", code, rs)
	}
	if len(rs) != 1+2*2+1+1+1 { // units, (sinkhole+resolve)*segments, broker, engine, uplink
		t.Fatalf("got %d results: %+v", len(rs), rs)
	}
}

func TestPostUpgradeCatchesEachFailureIndependently(t *testing.T) {
	base := func() PostUpgradeConfig {
		return PostUpgradeConfig{
			Units:        []string{"pi-fortress-broker.service"},
			Segments:     []Segment{{Name: "agent", IP: "10.77.0.1"}},
			BlockDomain:  "pi-fortress-block.test",
			PublicDomain: "example.com",
			BrokerSocket: "/run/pi-fortress/broker/broker.sock",
			EngineAddr:   "10.77.0.1:8080",
			UplinkServer: "9.9.9.9",
			UplinkName:   "example.com",
			Timeout:      time.Second,
			UnitActive:   func(string) bool { return true },
			Resolve: func(server, name string, _ time.Duration) ([]string, error) {
				if name == "pi-fortress-block.test" {
					return []string{"0.0.0.0"}, nil
				}
				return []string{"93.184.216.34"}, nil
			},
			DialUnix: func(string, time.Duration) error { return nil },
			DialTCP:  func(string, time.Duration) error { return nil },
		}
	}

	t.Run("dead unit", func(t *testing.T) {
		cfg := base()
		cfg.UnitActive = func(u string) bool { return false }
		r := find(t, PostUpgrade(cfg), "units", "post-upgrade")
		if r.Status != Fail {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("sinkhole not sinkholed", func(t *testing.T) {
		cfg := base()
		cfg.Resolve = func(server, name string, _ time.Duration) ([]string, error) { return []string{"1.2.3.4"}, nil }
		r := find(t, PostUpgrade(cfg), "sinkhole", "agent")
		if r.Status != Fail {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("public name does not resolve", func(t *testing.T) {
		cfg := base()
		cfg.Resolve = func(server, name string, _ time.Duration) ([]string, error) {
			if name == "pi-fortress-block.test" {
				return []string{"0.0.0.0"}, nil
			}
			return nil, errors.New("timeout")
		}
		r := find(t, PostUpgrade(cfg), "resolve", "agent")
		if r.Status != Fail {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("broker socket refuses", func(t *testing.T) {
		cfg := base()
		cfg.DialUnix = func(string, time.Duration) error { return errors.New("connection refused") }
		r := find(t, PostUpgrade(cfg), "broker", "fence")
		if r.Status != Fail {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("engine socket refuses", func(t *testing.T) {
		cfg := base()
		cfg.DialTCP = func(string, time.Duration) error { return errors.New("connection refused") }
		r := find(t, PostUpgrade(cfg), "engine", "fence")
		if r.Status != Fail {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("uplink unreachable", func(t *testing.T) {
		cfg := base()
		cfg.Resolve = func(server, name string, _ time.Duration) ([]string, error) {
			if server == cfg.UplinkServer {
				return nil, errors.New("network unreachable")
			}
			if name == "pi-fortress-block.test" {
				return []string{"0.0.0.0"}, nil
			}
			return []string{"93.184.216.34"}, nil
		}
		r := find(t, PostUpgrade(cfg), "uplink", "pi")
		if r.Status != Fail {
			t.Fatalf("%+v", r)
		}
	})
}

func TestPostUpgradeEmptyUnitsListWarnsRatherThanFails(t *testing.T) {
	cfg := PostUpgradeConfig{UnitActive: func(string) bool { return true }, UnitsSource: "/var/lib/pi-fortress/units.required: no such file"}
	rs := PostUpgrade(cfg)
	r := find(t, rs, "units", "post-upgrade")
	if r.Status != Warn {
		t.Fatalf("%+v", r)
	}
	if code := Report(io.Discard, rs); code != 0 {
		t.Fatalf("a warn-only ladder should not fail the exit code: %d", code)
	}
}
