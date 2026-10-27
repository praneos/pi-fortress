# Glossary

This is the one list of terms for Pi Fortress. Docs and code comments use these terms with these meanings. Code comments do not define terms: they use the terms from this file. To add a term, add a row here. The writing rules are in `style.md`.

| Term | Meaning |
|---|---|
| agent | The coding agent process. It runs in a VM or a container. |
| gateway | The Pi Fortress machine: a Raspberry Pi, or a VM in the lab. |
| origin server | The server that the agent sends a request to. |
| engine | The process that terminates TLS from the agent. It holds the CA key. |
| broker | The process that applies the credential fence. It holds `secrets.env`. |
| placeholder | A fake credential value that the agent has, for example `pf_SLOT_CLAUDE_OAT`. |
| live credential | The real value of a credential. Only the broker can read it. |
| live-looking token | A value in a request that has the format of a real credential. |
| strip | Remove a live-looking token from a request. The request then continues. |
| refuse | Stop a request and send an error response. Nothing goes to the origin server. |
| drop | Discard a packet or connection. Send no response. |
| core host | A host in `core.hosts`. The gateway manages credentials for these hosts. |
| eyeball network | A network of an ISP that connects homes or mobile phones to the internet, not servers. Its ASN is the unit that the eyeball check uses. |
| PSI | Pressure stall information. The kernel file `/proc/pressure` tells how much of the time tasks wait for memory, a CPU or I/O. |
| hardware watchdog | A timer in the hardware. It resets the gateway when systemd stops its signals, for example when the kernel hangs. |
