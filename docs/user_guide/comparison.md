<!-- Feature comparison with credential proxies, vaults, micro-VM sandboxes and host sandboxes, on verified facts only. -->
# Comparison

This page compares Pi Fortress with other tools that guard the credentials or the network access of an agent. Use it to see where Pi Fortress fits. Also use it to see where a different tool is the better choice.

Facts about other products come from their own public documentation. We checked these facts on 2026-10-10. If the documentation of a vendor does not say, the table says "not documented". Each of these tools also does something well that Pi Fortress does not do. Refer to **What each does better**, below.

| | Pi Fortress | Infisical Agent Vault / Agent Proxy | Gondolin (Earendil) | AgentSecrets, OneCLI | PipeLock | LiteLLM / Portkey virtual keys | Host sandboxes (Claude Code, Codex sandbox) |
|---|---|---|---|---|---|---|---|
| Traffic reaches it by | The only route out. Transparent TLS termination on the agent segment. No proxy variable to set. | `HTTPS_PROXY` variable, plus a CA | It is the runtime. The only network interface (NIC) of the guest is the host. | Explicit localhost proxy | Explicit proxy or sidecar on the host | The `base_url` of the agent | Same kernel as the agent |
| Enforced without agent cooperation | Yes. A process that ignores the proxy still has no other path out. | No¹ | Yes. It owns the runtime. | No. A skill with its own network access can still make its own calls. | No | No. The agent must use the `base_url`. | No. The enforcement is on the kernel that the agent runs on. |
| Runs on a separate kernel | Yes: Pi 5 or a separate VM | Optional. Their docs suggest a deployment on a different host. | Yes: a QEMU micro-VM (a lightweight virtual machine) | No | No | Usually² | No |
| Substitutes placeholders for live values | Yes, by credential kind and TLS name | Yes: vault token in, real header out | Yes: the host substitutes | Yes | No. It redacts. It never substitutes. | Yes, through a key exchange at the gateway³ | No |
| Strips foreign live tokens | Yes. It strips known token patterns to non-core hosts. It strips the kinds of other providers to core hosts. | No. A request to a host with no proxied service is "forwarded untouched". | Not documented | No. AgentSecrets redacts its own values in responses only. OneCLI: not documented. | Yes: encoding-aware redaction of live-looking secrets | LiteLLM: an Enterprise add-on redacts keys in prompts. Portkey: not documented. | No |
| Default posture | Allow, with a malware/phishing blocklist and a review log of unknown origin servers. [Paranoid mode](faq.md#paranoid-mode): allowlist only. | Allow. An unmatched host goes through. A block mode is an option. | Allowlist of hosts for HTTP and TLS. All other protocols except SSH are blocked. | AgentSecrets: deny, it blocks a domain that is not on the allowlist. OneCLI: not documented. | Allow in balanced mode, the default. Strict mode: allowlist only. | Only the model providers that you configure | Varies by tool |
| Licence, availability | Apache-2.0⁴ at the public release | MIT, except `ee/`. Agent Proxy launched in July 2026. | Apache-2.0 | AgentSecrets: MIT. OneCLI: Apache-2.0, except `ee/`. | Apache-2.0 plus ELv2 | Varies | Bundled with the tool |

¹ The agent gets to the proxy through `HTTPS_PROXY`. The proxy does not stop a process that ignores the variable.

² LiteLLM/Portkey is usually a remote service. But the agent holds a key that works from all locations that can reach the service.

³ The virtual key itself is a live credential toward the gateway.

⁴ Early access. The code is in review before its public release.

For a Claude subscription login, Pi Fortress also captures the OAuth refresh at the gateway. It stores the new token pair and gives the agent placeholders. We did not find this feature in the documentation of the other tools.

## What each does better

- **Gondolin**: it owns the runtime. Thus it controls files and processes, not only the network. Also, one micro-VM for each task is a cleaner unit than one long-lived VM, and its egress is an allowlist by default. Pi Fortress works with all runtimes, but it controls only the network.
- **Infisical**: it is a full team vault, with SDKs, access policies and audit logging. The agent proxy is only one part of it. Pi Fortress has a store for each slot and a text-based UI. It has no SDK and no multi-user policy.
- **PipeLock**: it detects secrets, also when they are encoded (base64, hex, homoglyphs). It tells you why it blocked something. It publishes a public bypass benchmark. Pi Fortress matches token patterns only as plain ASCII text. It has no published benchmark.
- **AgentSecrets, OneCLI**: you can install them in minutes, on the machine that you already have. You do not need a second box or VLANs (virtual networks).
- **LiteLLM, Portkey**: they give a budget for each key, rate limits, and routing across providers. Pi Fortress has only an hourly limit for each credential. This limit sends an alert or disables a slot. Pi Fortress has no budgets and no routing.
- **Host sandboxes**: they need no setup, because they come with the tool. Their limit is the reason for this project: the sandbox and the agent share one kernel.

The honest summary:

- All proxies here, except Gondolin, operate only if the agent decides to use them.
- Thus, with each of these proxies, the lock of the network is a separate step.
- Pi Fortress is that network lock, with credential custody built in.

The trade-offs are:

- A second machine.
- HTTP/1.1 only.
- IPv4 only.
- No support for clients that pin their own certificate.
