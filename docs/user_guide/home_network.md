<!-- Putting phones, laptops and TVs on their own filtered network behind the Pi. -->
# Home network

Pi Fortress can run a second network from the same Pi for the other devices in the house.
These are phones, laptops, smart TVs, and all other devices that are not AI agents. This guide
calls that network the **house segment**.

## What it does and does not do

| | |
|---|---|
| Blocks | Malware and phishing domains. Also a house block list that you control |
| Blocks the dodges | Drops DNS over HTTPS, DNS over TLS, and QUIC. An app can use these to hide or send its DNS queries around the Pi. Thus a device cannot secretly change to a resolver that ignores the block list |
| Filters | A new web connection to an address that your house DNS did not give recently. This is on by default. Refer to Settings below |
| Isolates | House devices cannot reach the agent network or the desk network. They cannot get the setup page or the certificate from these networks. The only exception is SSH from the admin device, if you allow it |
| Does not | Examine encrypted traffic. House devices have no certificate. There is no credential fence |
| Does not | Make a browsing report. But the Pi keeps DNS queries and blocked connections in its logs for troubleshooting. These logs show the names that devices resolved |
| Does not | Give schedules, time limits, or rules for each device. It is a filter. It is not a parental-control product |

For a comparison with the agent network, refer to [use cases](use_cases.md) and [FAQ](faq.md).

## What you need

- One more USB Ethernet adapter than your uplink and agent network use. The house network
    needs its own port. With the recommended cables (built-in port to the router, a USB adapter
    to the agent), this is a second USB adapter.
- A Wi-Fi router that can operate in access point (AP) mode:
    1. Set its Operation Mode to Access Point (also "AP mode" or "bridge mode").
        This disables the address sharing (NAT) of the router. It also disables the DHCP server
        of the router. A DHCP server gives addresses to devices.
    2. Connect a cable from the Pi USB adapter to a LAN port on the router.
    3. Do not connect a cable to the WAN/internet port of the router.
    4. Set a normal WPA2 or WPA3 Wi-Fi password. Do not leave the network open.
- Do not run two DHCP servers on the same network. After you set up the house network, the Pi
    is the only DHCP server on it.

## Set up house.env and apply

**Pi**
```
sudo nano /etc/pi-fortress/house.env
sudo pf apply
```

Set `HOUSE_IF` to the name of your USB adapter (for example `eth1`). This is the minimum. The
other keys have defaults that work. The table below gives the meaning of each key.

| key | default | meaning |
|---|---|---|
| `HOUSE_IF` | none, required | The USB Ethernet interface that connects to the LAN port of the router |
| `HOUSE_NET` | `10.78.0.0/24` | The address range of the house network |
| `HOUSE_IP` | `10.78.0.1` | The address of the Pi on the house network |
| `HOUSE_DHCP_START` | `10.78.0.100` | The first address that the Pi gives |
| `HOUSE_DHCP_END` | `10.78.0.199` | The last address that the Pi gives |
| `HOUSE_ADMIN_IP` | empty, no holes | The only house address that can SSH into the Pi. It is also the only house address that can SSH directly to the agent network. The Pi forwards this SSH |
| `HOUSE_DNS_UPSTREAM` | the Pi's main upstream | The plain DNS upstream for the house. Keep it empty when the Pi uses DNS over TLS. In that case, apply refuses it |
| `HOUSE_DOT_AUTH_NAME`, `HOUSE_DOT_IPS` | empty, share the Pi's | The DNS-over-TLS provider of the house. For example, a Control D profile `<id>.dns.controld.com` with `HOUSE_DOT_IPS="76.76.2.22 76.76.10.22"` (with quotes). The Pi must have its own `DOT_IPS` set. If `WG_IF` is set, this DNS goes through the tunnel |
| `HOUSE_BLOCK_DIRECT_IP` | on | Refer to Settings below |
| `HOUSE_BLOCK_HTTP` | off | Refer to Settings below |
| `HOUSE_BLOCK_VPN` | on | Refer to Settings below |
| `HOUSE_PRIVATE_DNS` | off | Refer to Settings below |
| `HOUSE_EGRESS` | strict | Refer to Settings below |
| `HOUSE_ALLOW_WIFI_CALLING`, `HOUSE_ALLOW_CALL_UDP` | off | Refer to Settings below |
| `HOUSE_ALLOW_WHATSAPP` | on | Refer to Settings below |
| `HOUSE_ALLOW_PORTS` | empty | More ports, for example `"tcp:27015-27030 udp:3074"` for a game. Use plain decimal. The Pi refuses a leading zero or `+` |
| `WG_IF` | empty, no tunnel | The WireGuard (VPN) interface for the house traffic to the internet, for example `wg0` from your VPN provider. If the tunnel stops, the house has no internet and no DNS. Traffic does not leak |
| `WG_BYPASS_MARK` | empty | Use it with `WG_IF`. The firewall mark for destinations that do not use the tunnel, for example banking apps that refuse VPN addresses. Keep it empty if you do not need it |

## Reserve the admin device

Select one device as the admin device for the house network. A laptop is the easiest. Only the
address of this device can SSH into the Pi from the house and reach the agent network. Use one
of these two methods to reserve the address:

- **On the Pi**, edit the reservation file:
    ```
    sudo nano /etc/pi-fortress/house.hosts
    ```
    Add a line `mac,ip,name`, for example `aa:bb:cc:dd:ee:ff,10.78.0.20,laptop`. Then run
    `sudo pf apply`.
- **In `sudo pf tui`**, go to **Home network → Devices**. Press `r` on the row of the device.
    Type a name, then an address. To accept the next free address, press Enter.

Then set `HOUSE_ADMIN_IP` in `house.env` to the same address. Apply again.

You can also SSH from that device into the desk. To do this, put the same address in the
segment file of the desk as `SSH_FROM=10.78.0.20`. Then apply ([pi_setup.md](pi_setup.md),
step 8). This opens SSH into the desk only. The desk gets no path back to the laptop or to
other devices on the house network.

## One SSID per VLAN

An access point can put each SSID on its own VLAN tag. If your access point can do this, the
same cable can carry a second network next to the house network. An example is an IoT network
on VLAN 30. That network is a plain segment (`IF=eth1.30` next to `HOUSE_IF=eth1`, refer to
[pi_setup.md](pi_setup.md), step 8). It is not part of the house network.

The tags are only as strong as the access point. A device on any SSID can tag its traffic onto
any network on that cable. Thus apply does these steps:

- It refuses SSH to the Pi or to the agent network from such a segment.
- It refuses the agent network on that cable.
- It shows a warning on each apply.

Use an access point or managed switch that maps each SSID to its own tag. It must not pass
tagged frames from its clients.

Devices on such a network usually expect DHCP, as the house network gives them an address. To
use DHCP, set `DHCP=on` in the segment file, with a `DHCP_START` and `DHCP_END` in the range of
the segment. The Pi then gives addresses on that network too. The Pi is the router and the DNS
for that network. The network gets no more trust than the house network.

If the access point has its own DHCP on that SSID, disable it. In AP mode, the access point has
no DHCP.

A device that needs a fixed address gets a reservation in
`/etc/pi-fortress/dhcp.<name>.hosts`. Use the same `mac,ip,name` lines as `house.hosts`. The
address can be in the range or outside it. Apply writes these lines into the DHCP server of
that network only. The TUI Devices page has no `r` for these devices. Thus edit the file and
run `sudo pf apply --local`. The [VLAN tutorial](tutorials/02-vlan-segments.md) has the
example.

## Settings you can change

Change these settings in `sudo pf tui`, **Home network → Settings**. The settings are in four
groups: Filtering, Apps & ports, DNS & VPN, and Network. The line below the list explains the
selected setting.

- For an on/off setting, Enter changes the value.
- For `HOUSE_EGRESS`, Enter goes to the next value: strict, audit, then open.
- For all other settings, Enter asks for a value.

Each change saves immediately. The change takes effect at the next apply. To apply, press `A`.
The Settings of the agent network are read-only: the agent network always blocks direct IP and
plain HTTP.

| setting | default | trade-off |
|---|---|---|
| `HOUSE_BLOCK_DIRECT_IP` | on | Stops an app or device that tries to go around the block list with a direct connection to an IP address. The Pi drops a plain HTTP connection to an address that your house DNS did not give. The Pi examines an HTTPS connection by the site name that it sends. The connection passes only if that name is not blocked and points to that address. Thus a phone with its own private DNS still works. Disable this setting only if a trusted device needs raw IP connections. |
| `HOUSE_BLOCK_HTTP` | off | When on, the Pi rejects all plain HTTP (port 80) connections, blocked or not. This can break captive portals, some smart TVs and printers, the Android "no internet" check, and old software update mirrors. It has no effect on HTTP on other ports. |
| `HOUSE_BLOCK_VPN` | on | Stops a device that runs its own VPN (WireGuard apps such as Mullvad, or OpenVPN). Also stops a device that tries to reach VPN, proxy, and DNS-bypass services. Also stops Tailscale and Cloudflare WARP. It does not control Wi-Fi calling. Wi-Fi calling has its own switch, `HOUSE_ALLOW_WIFI_CALLING`. Disable this setting if a person in the house needs a VPN. |
| `HOUSE_EGRESS` | strict | Controls the ports that the house can use. `strict`: allows web traffic and other encrypted ports (mail, push notifications), time sync, and ping. The Pi examines each connection on these ports by site name. `strict` also allows the mail ports TCP 143 (IMAP) and TCP 587 (SMTP submission). These ports start encryption later (STARTTLS), so the Pi does not examine them by site name. The Pi drops all other traffic. `audit`: logs the traffic that strict mode would drop, but lets it through. Use this mode for one day first to see the effect. `open`: allows all ports. In all modes, the house cannot reach the page of your router or other local networks. |
| `HOUSE_ALLOW_WIFI_CALLING` | off | Opens Wi-Fi calling (a VoIP-over-IPsec protocol). When on, an IKEv2 VPN app can also get through. |
| `HOUSE_ALLOW_WHATSAPP` | on | Lets the WhatsApp chat connection through. WhatsApp uses its own protocol. The Pi cannot examine this protocol by site name. Thus the Pi allows it only to the addresses of Meta. If you disable this setting, WhatsApp messages stop on the home network. |
| `HOUSE_ALLOW_CALL_UDP` | off | Opens the direct media ports of Meet, Zoom, Teams, WhatsApp, and FaceTime. When off, calls still work through the relay servers of the apps, with a small increase in delay. |
| `HOUSE_PRIVATE_DNS` | off | Lets a phone keep its own private DNS (the Android "Private DNS" hostname setting) on the home Wi-Fi. The Pi allows only the endpoint in `house_private_dns.domains` and the addresses in `house_private_dns.ips`. Other providers and other profiles stay blocked. The Pi does not see the DNS queries of that device. But the Pi still examines its HTTPS traffic by site name. |

## Lists

Edit these lists in `sudo pf tui`, **Home network → Filtering**. Press `a` to add a line, `d`
to delete a line, and `A` to apply. The last tab shows the block feeds for the home network.
Press `e` to enable or disable a feed.

| file | what it does |
|---|---|
| `house.domains` | More domains to block on the house network, in addition to the built-in feeds |
| `house_never_block.domains` | Domains that the house network must never block, also if a feed lists them |
| `house_direct_ip.allow` | Addresses that `HOUSE_BLOCK_DIRECT_IP` does not apply to. One IPv4 address or address range on each line. The widest range is `/24`. This list is separate from the list of the agent network |
| `house_private_dns.domains` | Your own private DNS endpoint, for example `abc123.dns.controld.com`. The Pi refuses a bare provider name |
| `house_private_dns.ips` | The addresses of that endpoint, one on each line (`dig +short` the endpoint). Single addresses only |

## Check it works

Run these commands from a device on the house Wi-Fi, except where the table gives a different
location.

!!! warning
    Never use `curl` to test a real blocklist host. A `dig` query is sufficient to prove that
    the host is sinkholed (sent to a dead address).

| command | where | good result |
|---|---|---|
| `dig ib.adnxs.com +short` | House device | last line is `0.0.0.0` (sinkholed) |
| `dig static.doubleclick.net +short` | House device | a real address (released by `house_never_block.domains`) |
| `dig example.com +short` | House device | a real address comes back |
| `curl -sS -o /dev/null -w '%{http_code}\n' https://example.com` | House device | `200`, no certificate warning |
| `curl --max-time 5 http://10.77.0.1/setup.sh` | House device | fails. The house cannot reach the setup page |
| `nc -zv -w 3 10.77.0.10 22` | Admin device only | succeeds only from the reserved admin address |
| `nc -zv -w 3 10.79.0.2 22` | Admin device, with the desk's `SSH_FROM` set | succeeds only from that address |
| `sudo pf status` | Pi | shows the `HOUSE_BLOCK_*` and `HOUSE_EGRESS` settings |
| `sudo journalctl -k -g house-audit` | Pi | in `audit` mode: the traffic that strict mode would drop. Use it to decide what to open |
| `sudo pf observe once` | Pi | shows the device as `house/<name>` |

## Device settings that break it

Symptom: `dig` resolves names correctly, but a browser says that it cannot connect or "could
not resolve".

| device setting | why it breaks | fix |
|---|---|---|
| A private DNS profile (Control D or similar, on a Mac or phone) | The Pi blocks DNS to other providers | Remove the profile. Or enable `HOUSE_PRIVATE_DNS` with your own endpoint in the lists, and set `HOUSE_DOT_AUTH_NAME` to the same profile |
| The secure DNS setting of a browser | The browser sends DNS directly to its own resolver, around the Pi | Disable the secure/private DNS setting of the browser for this network |
| A VPN app (Mullvad, Tailscale, WARP) | `HOUSE_BLOCK_VPN` drops it | Disable the VPN for this network, or disable the key |
| Android/GrapheneOS Private DNS set to a provider | Same as a DNS profile | Set Private DNS to automatic, or use `HOUSE_PRIVATE_DNS` |
| iCloud Private Relay or a similar relay feature | Traffic goes out through the relay, not through the Pi | Disable it for this network |

After you change the settings of a device, forget the Wi-Fi network and join it again. Or
flush the DNS cache of the device. The device then uses the Pi as its resolver again.

## Remove the home network

**Pi**
```
sudo rm /etc/pi-fortress/house.env
sudo pf apply
sudo nmcli con delete house-net
```

The apply stops the house DNS and DHCP service. It also removes the house firewall rules. The
last command removes the address of the Pi from the USB adapter. The agent network does not
change.
