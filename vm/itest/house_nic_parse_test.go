//go:build vagrant

package itest

import (
	"strings"
	"testing"
)

// The replug subtest attaches the house NIC again from the XML of the live
// domain. The XML must keep the MAC, the bridge and the PCI slot, and must
// lose the vnet target and the alias that libvirt gave the old device.
func TestHouseNICXML(t *testing.T) {
	dom := `<domain type='kvm'>
  <devices>
    <interface type='network'>
      <mac address='52:54:00:aa:bb:01'/>
      <source network='vagrant-libvirt'/>
      <target dev='vnet0'/>
      <model type='virtio'/>
      <alias name='net0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </interface>
    <interface type='bridge'>
      <mac address='52:54:00:AA:BB:03'/>
      <source bridge='pfhouse0'/>
      <target dev='vnet7'/>
      <model type='virtio'/>
      <alias name='net2'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x07' function='0x0'/>
    </interface>
  </devices>
</domain>`
	got := houseNICXML(dom, "52:54:00:aa:bb:03")
	for _, want := range []string{"<interface type='bridge'>", "52:54:00:AA:BB:03", "<source bridge='pfhouse0'/>", "slot='0x07'", "</interface>"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q lacks %q", got, want)
		}
	}
	for _, bad := range []string{"vnet7", "alias", "52:54:00:aa:bb:01"} {
		if strings.Contains(got, bad) {
			t.Fatalf("%q has %q", got, bad)
		}
	}
	if houseNICXML(dom, "52:54:00:aa:bb:99") != "" {
		t.Fatal("a MAC that is not in the domain gave an element")
	}
}
