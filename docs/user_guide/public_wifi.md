<!-- How to keep the Pi safe when its uplink is Wi-Fi you do not control. -->
# Pi on public Wi-Fi

This page is for a Pi with an uplink on a network that you do not control. The uplink is the
internet connection of the Pi, often the interface `wlan0`. Examples of such networks are a
cafe, a hotel, an airport, and a shared office.

On such a network, all other users of the Wi-Fi are neighbors of the Pi. A neighbor can:

- Scan the Pi.
- Connect to its open ports.
- Answer its ARP requests. Devices use ARP to find the hardware address of other devices on
    the local network.
- Answer its DNS requests.
- Read plain-text traffic.

The goal of this page: **on the uplink, the Pi answers only what it must answer.**

## 1. Why not just use ufw

`ufw` is a popular Linux firewall tool. Pi Fortress does not use it. Do not add it.

| Question | Answer |
|---|---|
| Does the Pi need ufw? | No. The Pi has its own firewall. By default, this firewall drops all input. |
| Would ufw help? | No. Each time the gateway applies its settings, it writes the full firewall again. Thus the next apply removes the ufw rules. |
| Would ufw hurt? | Yes. ufw also writes rules at boot. If two tools control one firewall, you cannot know which rule is active. |

Only the gateway firewall must manage rules on the Pi.

## 2. What is already safe

These protections are on by default, on all Pis, on all uplinks.

| Item | How |
|---|---|
| Incoming traffic on the uplink | Dropped by default. Only SSH (rate limited), DHCP replies, and ping (rate limited) come in. The Pi drops all other traffic. |
| Forwarding | Dropped by default. The Pi forwards nothing from the uplink to the agent, house, or desk segments. |
| Services | DNS, the engine, the web server, and other internal services listen only on internal addresses. Only SSH listens on all addresses. The firewall guards SSH. |
| IPv6 | Off on the Pi. The firewall also drops IPv6 on the uplink in the two directions. Thus, if a network enables IPv6 again, no IPv6 traffic goes through. |
| ARP | On the uplink, the Pi answers ARP only for its uplink address. Thus a neighbor cannot find the agent or house addresses from the uplink. |
| Spoofing protection | Reverse path filtering is on. The Pi ignores a packet that claims to come from an address that cannot reach the Pi on that path. The Pi ignores ICMP redirects and source routes (methods to send traffic on a different path). SYN cookies (a defense against connection-flood attacks) are on. |
| SSH | Keys only, no root login. The install sets this if it found a key. |
| Updates | Automatic security updates are on. |

## 3. Close the uplink: `UNTRUSTED_UPLINK=1`

When this setting is on, the uplink gets these changes:

| Change | Effect |
|---|---|
| No SSH from the uplink | SSH is reachable only from your other segments. It is not reachable from the uplink |
| No ping from the uplink | The uplink does not answer ping |
| DHCP still works | The Pi can still get its own address from the network |
| No name broadcasts out | The Pi does not send mDNS and LLMNR on the uplink. These protocols broadcast the name of a device on the local network |

The Pi still reaches the internet. Replies to connections that the Pi started still come back.

### You need another way in first

This setting closes SSH on the uplink. Thus the gateway refuses to apply it unless one of these
paths is already set up:

| Way in | Where it is set |
|---|---|
| A house admin device | in the house network settings |
| A desk or other admin segment | marked as an admin segment |

If neither path is set up, the gateway refuses the apply. The message says that the only
remaining way in is a keyboard and screen connected to the Pi. In this case, nothing changes.

!!! warning
    This check proves only that an admin path is configured. It does not prove that the cable
    is connected. Before you apply, SSH to the Pi on that path (for example, from the house
    admin device). Run the apply from that session.

### Turn it on, check it, turn it off

**Pi**
```sh
echo UNTRUSTED_UPLINK=1 | sudo tee -a /etc/pi-fortress/net.env.local
sudo pf apply --local
sudo nft list chain inet fortress input | grep 'dport 22'
```
A software update does not overwrite `net.env.local`. After the apply, examine the output of
the last command. It must not show a line with the uplink interface (for example `wlan0`). The
house or desk SSH line stays.

You can also set the same key in `sudo pf tui`, **System → Settings**. To enable it there:

- The TUI asks first. The prompt says that SSH on the uplink stops at the next apply. It also
    names an admin segment as the way back in.
- Only `y` continues. All other keys cancel and write nothing. This includes Esc and a second
    Enter.

To disable it there, press Enter one time. The TUI does not ask, because this gives back only a way
in that you had before.

When you are on a trusted network again, set the same key to `0` and apply again. In the TUI,
press Enter one time on that row, then press `A` to apply. A desktop on the same Wi-Fi as the Pi can
then SSH to the Wi-Fi address of the Pi, as before.

## 4. Set up a separate Wi-Fi profile

The firewall cannot hide what the Pi sends when it joins a network. Make a separate connection
profile for each public network that you use. Do not change your home profile. Your home router
can give the Pi a fixed address by its hardware (MAC) address.

**Pi**
```sh
sudo nmcli con add type wifi ifname wlan0 con-name public ssid "NETWORK NAME" \
  wifi.cloned-mac-address random ipv4.dhcp-send-hostname no ipv6.method disabled \
  connection.autoconnect no
sudo nmcli con modify public wifi-sec.key-mgmt wpa-psk wifi-sec.psk "PASSWORD"
sudo nmcli con up public
```
On an open network with no password, do not run the second command. When you no longer need
the network, run `sudo nmcli con delete public`.

| Setting | Why |
|---|---|
| `wifi.cloned-mac-address random` | A new hardware address each time. Thus the network cannot track the Pi |
| `ipv4.dhcp-send-hostname no` | The DHCP server of the network does not get the hostname of the Pi |
| `ipv6.method disabled` | No IPv6 address on this network. This is in addition to the firewall drop |
| `connection.autoconnect no` | The Pi never joins this network again automatically |

## 5. Check the Pi

**On the Pi:**

| Check | Command | Good result |
|---|---|---|
| IPv6 dropped on the uplink | `sudo nft list ruleset \| grep '"wlan0" meta nfproto ipv6'` | 2 lines, one incoming, one outgoing |
| No IPv6 address | `ip -6 addr show dev wlan0` | empty |
| ARP settings | `sysctl net.ipv4.conf.all.arp_ignore net.ipv4.conf.all.arp_announce` | `1` and `2` |
| Listeners | `sudo ss -tulpn` | only SSH on all addresses, and chronyd on UDP 123 when the Pi has a house or a plain segment. The input chain drops UDP 123 from the uplink |
| SSH is keys only | `sudo sshd -T \| grep -Ei '^(passwordauthentication\|kbdinteractiveauthentication\|permitrootlogin) '` | all `no` |
| Uplink closed | `sudo nft list chain inet fortress input \| grep wlan0` | no `dport 22`, no `icmp` |

**On a desktop or another machine on the same Wi-Fi as the Pi:**

| Check | Command | Good result |
|---|---|---|
| SSH | `nc -zv -w3 <Pi Wi-Fi address> 22` | fails when the uplink is closed. Works when the uplink is open |
| Other ports | `nc -zv -w3 <Pi Wi-Fi address> 53` (also try 80, 443, 853, 8080) | fails |

## 6. What is not covered

These are known gaps. The firewall cannot fix them.

| Gap | What a neighbor or the network owner can do | What you can do |
|---|---|---|
| Plain DNS to your upstream resolver | See each name that the Pi resolves. Send false answers. HTTPS still examines certificates. Thus an HTTPS connection to a false address fails the certificate check and sends no data. | Enable DNS over TLS (`DOT_AUTH_NAME` and `DOT_IPS` in [pi_setup.md](pi_setup.md), step 4). |
| Traffic metadata | See the addresses that the Pi connects to. See the server names in its TLS connections. | Use a trusted network for sensitive work. The WireGuard option (`WG_IF`) applies only to the house segment. It does not apply to the traffic of the Pi or of the agent. |
| Time sync (NTS, the authenticated clock-sync protocol) | Block it. The Pi then keeps the clock of its RTC, and the clock slowly drifts. The network cannot set a false time, because NTS authenticates each answer. | If sites suddenly fail certificate checks, examine the clock of the Pi with `timedatectl` and `chronyc sources`. |
| A captive portal login page (the page that a public Wi-Fi shows before it gives access) | The Pi cannot open the login page itself. | Log in from the browser of the desktop. Its traffic goes out through the Pi, with the hardware address of the Pi. |
| A fake access point with the same name | Get in the middle of your connection. | The items above limit the damage. Use networks that need a password, when possible. |
| A stolen Pi | Read the storage card. | This page does not cover this gap. By default, the SD card is not encrypted. Refer to `pf enroll seal` in [faq.md](faq.md). |

## See also

- [pi_setup.md](pi_setup.md): how to set up a real Pi
- [home_network.md](home_network.md): the filtered home network behind the Pi
