package install

import "testing"

const piBookworm = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
`

const piTrixie = `PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION_CODENAME=trixie
ID=debian
`

const debian12 = piBookworm
const debian13 = piTrixie

const ubuntu2404 = `PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
`

const ubuntu2204 = `PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION_CODENAME=jammy
ID=ubuntu
`

const piModel = "Raspberry Pi 5 Model B Rev 1.0\x00"

func TestSupportedTargets(t *testing.T) {
	cases := []struct {
		name      string
		arch      string
		osRelease string
		model     string
		wantOK    bool
	}{
		{"pi-bookworm-arm64", "arm64", piBookworm, piModel, true},
		{"pi-trixie-arm64", "arm64", piTrixie, piModel, true},
		{"generic-debian-arm64-no-pi-model", "arm64", debian12, "", false},
		{"debian12-amd64", "amd64", debian12, "", true},
		{"debian13-amd64", "amd64", debian13, "", true},
		{"ubuntu2404-amd64", "amd64", ubuntu2404, "", true},
		{"ubuntu2204-amd64-refused", "amd64", ubuntu2204, "", false},
		{"pi-model-amd64-ok", "amd64", piBookworm, piModel, true}, // amd64 rule does not look at Model at all
		{"arm-32-refused", "arm", piBookworm, piModel, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := DetectTargetFrom(c.arch, c.osRelease, c.model)
			_, ok := target.Supported()
			if ok != c.wantOK {
				t.Fatalf("Supported() = %v, want %v (target=%+v)", ok, c.wantOK, target)
			}
			if !ok {
				if msg := target.Refusal(); msg == "" {
					t.Fatal("Refusal() empty on an unsupported target")
				}
			}
		})
	}
}

func TestParseOSRelease(t *testing.T) {
	kv := ParseOSRelease(ubuntu2404)
	if kv["ID"] != "ubuntu" || kv["VERSION_ID"] != "24.04" || kv["VERSION_CODENAME"] != "noble" {
		t.Fatalf("unexpected parse: %+v", kv)
	}
}
