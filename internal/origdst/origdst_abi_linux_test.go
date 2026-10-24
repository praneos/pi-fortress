package origdst

import (
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// origDstBufLen mirrors the buffer that getOrigDst gives to getsockopt,
// make([]byte, 16), and the optlen it passes, uint32(len(buf)).
const origDstBufLen = 16

// sockaddrInABI is struct sockaddr_in, which the kernel copies out for
// SO_ORIGINAL_DST, plus the optlen type and the option number.
type sockaddrInABI struct {
	size, family, port, addr, zero uintptr
	socklen                        uintptr // sizeof(socklen_t)
	soOriginalDst                  int
	afInet, afInet6                int
}

var origDstABI = map[string]sockaddrInABI{
	// include/uapi/linux/in.h: struct sockaddr_in { sin_family u16 @0;
	// sin_port be16 @2; sin_addr u32 @4; __pad[8] @8 }, size 16.
	// include/linux/syscalls.h: sys_getsockopt optlen is int __user * (4).
	// include/linux/socket.h: AF_INET 2, AF_INET6 10.
	// include/uapi/linux/netfilter_ipv4.h: SO_ORIGINAL_DST 80.
	"amd64": {size: 16, family: 0, port: 2, addr: 4, zero: 8, socklen: 4, soOriginalDst: 80, afInet: 2, afInet6: 10},
	// Same headers; sockaddr_in has no arch-specific padding.
	"arm64": {size: 16, family: 0, port: 2, addr: 4, zero: 8, socklen: 4, soOriginalDst: 80, afInet: 2, afInet6: 10},
}

func TestSockaddrInLayout(t *testing.T) {
	k, ok := origDstABI[runtime.GOARCH]
	if !ok {
		t.Skipf("no ABI row for GOARCH %s", runtime.GOARCH)
	}
	var sa syscall.RawSockaddrInet4
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"Sizeof(RawSockaddrInet4)", unsafe.Sizeof(sa), k.size},
		{"SizeofSockaddrInet4", syscall.SizeofSockaddrInet4, k.size},
		{"Offsetof(Family)", unsafe.Offsetof(sa.Family), k.family},
		{"Offsetof(Port)", unsafe.Offsetof(sa.Port), k.port},
		{"Offsetof(Addr)", unsafe.Offsetof(sa.Addr), k.addr},
		{"Offsetof(Zero)", unsafe.Offsetof(sa.Zero), k.zero},
		{"buffer length", origDstBufLen, k.size},
		{"optlen = Sizeof(uint32)", unsafe.Sizeof(uint32(0)), k.socklen},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, kernel %s = %d", c.name, c.got, runtime.GOARCH, c.want)
		}
	}
	if soOriginalDst != k.soOriginalDst {
		t.Errorf("soOriginalDst = %d, kernel SO_ORIGINAL_DST = %d", soOriginalDst, k.soOriginalDst)
	}
	if afInet != k.afInet || afInet != syscall.AF_INET {
		t.Errorf("afInet = %d, kernel AF_INET = %d, syscall.AF_INET = %d", afInet, k.afInet, syscall.AF_INET)
	}
	if afInet6 != k.afInet6 || afInet6 != syscall.AF_INET6 {
		t.Errorf("afInet6 = %d, kernel AF_INET6 = %d, syscall.AF_INET6 = %d", afInet6, k.afInet6, syscall.AF_INET6)
	}
}

// TestParseInet4ReadsKernelLayout feeds parseInet4 the bytes of a
// sockaddr_in as the kernel writes it (host-order family, network-order
// port), not a hand-written byte slice.
func TestParseInet4ReadsKernelLayout(t *testing.T) {
	sa := syscall.RawSockaddrInet4{Family: syscall.AF_INET, Addr: [4]byte{192, 0, 2, 1}}
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	p[0], p[1] = 0x1f, 0x90 // 8080 big-endian
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	got, err := parseInet4(append([]byte(nil), raw...))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "192.0.2.1:8080" {
		t.Fatalf("got %s, want 192.0.2.1:8080", got)
	}
}
