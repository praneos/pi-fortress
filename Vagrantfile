# frozen_string_literal: true

def load_net_env
  env = {}
  File.readlines(File.join(__dir__, "vm/pi/net.env"), chomp: true).each do |line|
    next if line.empty? || line.start_with?("#")
    key, value = line.split("=", 2)
    env[key] = value
  end
  env
end

NET = load_net_env

# Vagrant needs a dotted netmask. net.env has prefixes, and the desk
# segment is a /30. The code calculates the netmask. Thus net.env stays
# the one place that records the topology.
def netmask_of(cidr)
  bits = cidr.split("/", 2)[1].to_i
  mask = (0xffffffff << (32 - bits)) & 0xffffffff
  [24, 16, 8, 0].map { |s| (mask >> s) & 0xff }.join(".")
end

# Host-guest channels and emulated devices that this lab does not use.
# They are off in the current bento box, but only by chance. A box update
# can enable any of them, and vrde is already on (inert only while no
# Extension Pack is installed). Each is hypervisor code that a hostile
# guest can reach. Thus they are pinned off for each VM, and
# `make agent-audit` reads them back.
VB_LOCKDOWN = %w[
  --clipboard-mode disabled --drag-and-drop disabled --audio-enabled off
  --usb-ohci off --usb-ehci off --usb-xhci off --vrde off
  --nested-hw-virt off --uart1 off --lpt1 off
].freeze

# What an agent VM gets from the checkout: its own scripts, the topology,
# and the public CA of the lab gateway as a fallback for a gateway that
# does not answer yet. Not the rest: the tree holds alert.url, and its
# path is the bearer token of the webhook.
AGENT_RSYNC_ARGS = %w[
  --verbose --archive --delete --delete-excluded -z --copy-links
  --include=/vm/ --include=/vm/agent/ --include=/vm/agent/**
  --include=/vm/pi/ --include=/vm/pi/net.env
  --include=/vm/policy/ --include=/vm/policy/generated/
  --include=/vm/policy/generated/*-ca.pem --exclude=*
].freeze

Vagrant.configure("2") do |config|
  config.vm.box = "bento/debian-12"
  config.vm.box_check_update = false
  config.vm.boot_timeout = 600
  config.vm.synced_folder ".", "/vagrant"

  config.vm.define "pi", primary: true do |pi|
    pi.vm.hostname = "pi-fortress"
    pi.vm.network "private_network",
                  ip: NET["PI_IP"],
                  netmask: "255.255.255.0",
                  virtualbox__intnet: NET["INTNET_NAME"]
    # The house segment. It is the only segment with DHCP, not static
    # addresses. Thus it is the only part of a lab that tests the dnsmasq
    # DHCP of the Pi: the range, house.hosts, the lease file and all
    # code that reads them.
    pi.vm.network "private_network",
                  ip: NET["LAB_HOUSE_IP"],
                  netmask: netmask_of(NET["LAB_HOUSE_NET"]),
                  virtualbox__intnet: NET["LAB_HOUSE_INTNET"]
    # The desk segment. It is untagged here, because a VirtualBox internal
    # network has no 802.1Q tags. Thus this is eth3, not eth0.79, and
    # segments.d/desk.env names it without a dot. All layers above the link
    # layer are the same as the segment that the real Pi runs.
    pi.vm.network "private_network",
                  ip: NET["DESK_IP"],
                  netmask: netmask_of(NET["DESK_NET"]),
                  virtualbox__intnet: NET["DESK_INTNET"]
    pi.vm.provider "virtualbox" do |vb|
      vb.name = "pi-fortress"
      vb.memory = 1024
      vb.cpus = 1
      vb.customize ["modifyvm", :id, "--natdnsproxy1", "off"]
      vb.customize ["modifyvm", :id, *VB_LOCKDOWN]
      vb.customize ["modifyvm", :id, "--natdnshostresolver1", "off"]
    end
    pi.vm.provision "bootstrap", type: "shell", path: "vm/pi/provision.sh", env: { "PF_LAB" => "1" }
    pi.vm.provision "apply", type: "shell", path: "vm/pi/apply.sh", run: "always"
  end

  # A house device. All other VMs in this lab hold a static address that
  # Vagrant assigned. This one asks the Pi for a lease. That is the only
  # way that a lab tests the DHCP half of dnsmasq.
  config.vm.define "house", autostart: false do |house|
    house.vm.hostname = "house"
    house.vm.synced_folder ".", "/vagrant", type: "rsync",
                           rsync__exclude: [".git/", ".vagrant/", "vendor/", "bin/"]
    # auto_config: false. Vagrant would write a static address here.
    # This VM must not have a static address. lab.sh runs the DHCP
    # client.
    house.vm.network "private_network",
                     auto_config: false,
                     virtualbox__intnet: NET["LAB_HOUSE_INTNET"]
    house.vm.provider "virtualbox" do |vb|
      vb.name = "pi-fortress-house"
      vb.memory = 512
      vb.cpus = 1
      vb.customize ["modifyvm", :id, "--natdnsproxy1", "off"]
      vb.customize ["modifyvm", :id, *VB_LOCKDOWN]
      vb.customize ["modifyvm", :id, "--natdnshostresolver1", "off"]
      # Pinned so that house.hosts can reserve an address for it. On a
      # real network, the MAC also identifies a house device.
      vb.customize ["modifyvm", :id, "--macaddress2", NET["LAB_HOUSE_MAC"].delete(":")]
    end
    house.vm.provision "bootstrap", type: "shell", inline: "/vagrant/vm/house/lab.sh bootstrap"
    house.vm.provision "lease", type: "shell", inline: "/vagrant/vm/house/lab.sh lease", run: "always"
  end

  # The desk seat: a plain segment. Thus it resolves through the Pi with the
  # blocklists of the agents and no TLS inspection, with NAT to the uplink
  # and isolation from all other segments. It is the tier-1 stand-in for the
  # desktop that vm/desk/setup.sh configures (docs/lab.md). It is untagged,
  # because a VirtualBox internal network cannot carry a tag.
  config.vm.define "desk", autostart: false do |desk|
    desk.vm.hostname = "desk"
    # Read-only for the same reason as the agents (refer to below): root in
    # a VM must not be able to write the Vagrantfile or Makefile of the host.
    desk.vm.synced_folder ".", "/vagrant", type: "rsync",
                          rsync__exclude: [".git/", ".vagrant/", "vendor/", "bin/"]
    desk.vm.network "private_network",
                    ip: NET["DESK_SEAT_IP"],
                    netmask: netmask_of(NET["DESK_NET"]),
                    virtualbox__intnet: NET["DESK_INTNET"]
    desk.vm.provider "virtualbox" do |vb|
      vb.name = "pi-fortress-desk"
      vb.memory = 512
      vb.cpus = 1
      vb.customize ["modifyvm", :id, "--natdnsproxy1", "off"]
      vb.customize ["modifyvm", :id, *VB_LOCKDOWN]
      vb.customize ["modifyvm", :id, "--natdnshostresolver1", "off"]
    end
    desk.vm.provision "bootstrap", type: "shell", inline: "/vagrant/vm/desk/lab.sh bootstrap"
    # The address stays after a reboot, because Vagrant writes it. The
    # default route and the resolver do not stay. Thus the code applies them again.
    desk.vm.provision "routes", type: "shell", inline: "/vagrant/vm/desk/lab.sh routes", run: "always"
  end

  # One or more agent VMs. When bridged (AGENT_BRIDGE), they are on the
  # real cable to the Pi. After the VLAN split, that cable is a tagged child
  # device. The VMs see only VLAN 20, untagged. A frame that they tag
  # themselves arrives at the Pi with two tags, and the Pi drops it.
  # They share one bridge. Thus they are one trust tier, not three.
  agent_count = [ENV["AGENT_COUNT"].to_i, 1].max
  bridge = ENV["AGENT_BRIDGE"].to_s
  agent_octets = NET["AGENT_IP"].split(".")
  mgmt_octets = NET["LAB_MGMT_IP"].split(".")
  (1..agent_count).each do |n|
    name = n == 1 ? "agent" : "agent#{n}"
    vb_name = n == 1 ? "pi-fortress-agent" : "pi-fortress-agent#{n}"
    ip = (agent_octets[0, 3] + [(agent_octets[3].to_i + n - 1).to_s]).join(".")
    mgmt_ip = (mgmt_octets[0, 3] + [(mgmt_octets[3].to_i + n - 1).to_s]).join(".")
    # The trigger below writes this only after ssh to this VM works
    # through the sanctioned path: over the bridge through the Pi, or
    # over the host-only management NIC when not bridged.
    # Until then, Vagrant uses the VirtualBox NAT adapter to reach the
    # box. Thus a failed first provision cannot leave it with no access.
    # The marker holds the mode of the proof ("lab" or the bridge
    # device). Bridged and unbridged provisioning leave different
    # addresses in the guest. Thus a marker from the other mode, or an
    # empty marker from before the mode was recorded, counts as not
    # provisioned. The NAT cable comes back and the proof runs again in
    # this mode.
    marker = ".vagrant/pf-#{name}-provisioned"
    mode = bridge.empty? ? "lab" : bridge
    marker_path = File.join(__dir__, marker)
    provisioned = File.exist?(marker_path) && File.read(marker_path).strip == mode

    config.vm.define name do |agent|
      agent.vm.hostname = name
      # One-way share, in the two modes. The default vboxsf mount at the top
      # of this file is read-write. Thus root in an agent VM could edit the
      # Vagrantfile or the Makefile that the operator runs next on the host.
      # A hostile agent would then get to the host without the hypervisor.
      # A "ro" mount on the guest side does not help: root in the VM mounts
      # it again. rsync is the only method with no guest-to-host path. Thus
      # the agent gets what routes.sh reads (net.env and the CA pems), and
      # nothing goes back.
      agent.vm.synced_folder ".", "/vagrant", type: "rsync",
                             rsync__args: AGENT_RSYNC_ARGS,
                             rsync__exclude: [".git/", ".vagrant/", "vendor/", "bin/"]
      if bridge.empty?
        # auto_config: false, on the two NICs, for the same reason as in
        # the bridged branch. Vagrant configures networks over the ssh
        # session. After the code cuts the NAT adapter, that session uses
        # the management NIC. That NIC has no address until a script
        # configures it. provision.sh and routes.sh own the addresses.
        agent.vm.network "private_network",
                         ip: ip,
                         netmask: "255.255.255.0",
                         auto_config: false,
                         virtualbox__intnet: NET["INTNET_NAME"]
        # The management NIC, a real host-only network. The host can
        # reach it. Thus vagrant ssh does not need the NAT adapter. The
        # trigger below cuts that adapter after this path works.
        # It is defined after the intnet, so the intnet stays the first
        # non-NAT NIC. provision.sh uses that to find the cable.
        agent.vm.network "private_network",
                         ip: mgmt_ip,
                         netmask: netmask_of(NET["LAB_MGMT_NET"]),
                         auto_config: false
      else
        # auto_config: false. The Debian path of Vagrant writes this
        # interface with no gateway. It then restarts it over the ssh
        # session that uses it after the NAT adapter is cut. provision.sh
        # and routes.sh own the address, the route and the resolver.
        agent.vm.network "public_network",
                         ip: ip,
                         netmask: "255.255.255.0",
                         bridge: bridge,
                         auto_config: false
      end
      # After the sanctioned path works (the marker that the trigger
      # writes), ssh uses it: the management NIC when not bridged, the
      # bridged address through the Pi. Until then, Vagrant reaches the
      # box over the NAT port-forward. A failed first provision also
      # uses that path.
      if provisioned
        agent.ssh.host = bridge.empty? ? mgmt_ip : ip
        agent.ssh.port = 22
      end
      agent.vm.provider "virtualbox" do |vb|
        vb.name = vb_name
        vb.memory = 512
        vb.cpus = 1
        vb.customize ["modifyvm", :id, "--natdnsproxy1", "off"]
        vb.customize ["modifyvm", :id, *VB_LOCKDOWN]
        vb.customize ["modifyvm", :id, "--natdnshostresolver1", "off"]
        # The guest-side nft lock cannot control the NAT adapter. It is
        # a userspace path out of the VirtualBox process on the host.
        # Thus it would use the Wi-Fi of the host and go around the Pi.
        # Root in the VM can remove the guest lock. It cannot connect a cable.
        vb.customize ["modifyvm", :id, "--cableconnected1", provisioned ? "off" : "on"]
      end
      agent.vm.provision "bootstrap", type: "shell", path: "vm/agent/provision.sh",
                         env: { "PF_AGENT_IP" => ip, "PF_BRIDGED" => bridge.empty? ? "0" : "1",
                                "PF_MGMT_IP" => bridge.empty? ? mgmt_ip : "",
                                "PF_AGENT_SUDO" => ENV["AGENT_SUDO"].to_s == "1" ? "1" : "0" }
      agent.vm.provision "routes", type: "shell", path: "vm/agent/routes.sh", run: "always",
                         env: { "PF_AGENT_IP" => ip }

      # The address that the sanctioned path reaches: the bridged address
      # over the bridge through the Pi, or the host-only management address
      # when not bridged. In the two cases, the trigger cuts the NAT adapter
      # only after ssh to that address answers. If ssh does not answer, it
      # arms the NAT cable again, but only until the first proof. After
      # that, root in the VM could stop sshd to get the cable back. Thus a
      # failure keeps it cut and names the command that arms it again.
      ssh_ip = bridge.empty? ? mgmt_ip : ip
      %i[up provision reload].each do |cmd|
        agent.trigger.after cmd do |t|
          t.name = "cut the NAT adapter on #{vb_name}"
          t.run = { path: "vm/agent/cut-nat.sh", args: [vb_name, ssh_ip, name, mode] }
        end
      end

      agent.trigger.after :destroy do |t|
        t.name = "forget #{name}"
        t.run = { inline: "rm -f #{marker}", privileged: false }
      end
    end
  end
end
