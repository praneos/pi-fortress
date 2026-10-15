<!-- Why Pi Fortress exists: the problem, with sourced incidents and numbers, then the answer. -->
# Why it exists

AI agents now work with real keys: API keys, OAuth tokens, GitHub tokens. They also read text from strangers all day: web pages, issues, packages and MCP tools. That text can steer them. Attackers know this. They now hunt the keys that agents and developer machines hold.

## The numbers

<div class="pf-charts">
<div class="pf-chart" data-title="CVEs published per year" data-unit="thousand" data-labels="2019,2020,2021,2022,2023,2024,2025" data-values="17.3,18.3,20.1,25.1,28.8,40.0,48.2"><p>CVEs published per year</p><ul><li>2019: 17.3 thousand</li><li>2020: 18.3 thousand</li><li>2021: 20.1 thousand</li><li>2022: 25.1 thousand</li><li>2023: 28.8 thousand</li><li>2024: 40.0 thousand</li><li>2025: 48.2 thousand</li></ul></div>
<div class="pf-chart" data-title="Secrets leaked on public GitHub" data-unit="million" data-labels="2022,2023,2024,2025" data-values="10.0,12.8,23.8,29.0"><p>Secrets leaked on public GitHub</p><ul><li>2022: 10.0 million</li><li>2023: 12.8 million</li><li>2024: 23.8 million</li><li>2025: 29.0 million</li></ul></div>
</div>

- **29 million** new secrets leaked on public GitHub in 2025, 34% more than in 2024, by the count of the 2026 report. This is the largest jump in one year that GitGuardian has recorded ([GitGuardian, 2026](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html)).
- **1,275,105** of these leaked secrets were for AI services, 81% more than in 2024. Eight of the ten fastest-growing types of leaked secret were AI-related ([GitGuardian, 2026](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html)).
- **24,008** secrets were in MCP configuration files on public GitHub. 2,117 of them were valid ([GitGuardian, 2026](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html)).
- **64%** of the secrets that leaked in 2022 were still valid in 2026. A revocation often does not occur ([GitGuardian, 2026](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html)).

## Recent incidents

| When | What happened |
|---|---|
| March 2025 | **VMware ESXi.** VMware fixed three zero-days that let an attacker escape a VM to the hypervisor. Attackers used them before the fix, and ransomware groups use them now ([Security Affairs](https://securityaffairs.com/187637/security/cve-2025-22225-in-vmware-esxi-now-used-in-active-ransomware-attacks.html), [The Register](https://www.theregister.com/2026/01/09/china_esxi_zerodays/)). |
| May 2025 | **Pwn2Own Berlin.** Researchers escaped VMware ESXi for the first time in the history of the contest, and also escaped VirtualBox and VMware Workstation ([CSO Online](https://csoonline.com/article/3989785/ethical-hackers-exploited-zero-day-vulnerabilities-against-popular-os-browsers-vms-and-ai-frameworks.html)). |
| August 2025 | **s1ngularity.** Malicious versions of the Nx package on npm ran on developer machines. The malware told the AI command-line tools on each machine (Claude, Gemini, Q) to search for secrets. 2,349 secrets leaked, most of them GitHub tokens ([GitGuardian](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/)). |
| September and November 2025 | **Shai-Hulud.** A self-spreading npm worm stole npm and GitHub tokens from developer machines and used them to infect more packages. Its second wave, in November, exposed about 400,000 raw secrets in 30,000 GitHub repositories ([BleepingComputer](https://www.bleepingcomputer.com/news/security/shai-hulud-20-npm-malware-attack-exposed-up-to-400-000-dev-secrets/)). |
| April 2026 | **Claude Mythos Preview.** Anthropic reported a model that finds zero-days and writes working exploits for every major OS and browser. It found a guest-to-host flaw in a production hypervisor. It is not public ([Help Net Security](https://www.helpnetsecurity.com/2026/04/08/anthropic-claude-mythos-preview-identify-vulnerabilities/)). |
| September 2026 | **A hijacked AI coding session.** Mandiant reported an attacker who took over an active AI coding-assistant session at a software company. The session installed a poisoned package and an infostealer. The attacker stole GitHub OAuth tokens and spread Shai-Hulud to about 100 internal repositories. Mandiant recommends that raw API keys and long-lived OAuth tokens stay out of direct reach ([The Hacker News](https://thehackernews.com/2026/09/attacker-hijacks-ai-coding-assistant.html)). |
| September 2026 | **Credential theft at machine speed.** Google Threat Intelligence reported an autonomous, multi-agent attack framework. It took thousands of API and cloud credentials in less than six hours ([The Hacker News](https://thehackernews.com/2026/09/autonomous-ai-agents-compromise.html)). |

## The pattern

1. The machine of the agent holds real keys, in configuration files, environment variables and credential files.
2. Something that the agent trusts runs code or gives instructions: a package, an issue, a tool.
3. The keys go out in minutes, to an address that the attacker selects.
4. The keys stay valid for a long time after the theft.

## The answer

Pi Fortress removes step 1 and blocks step 3.

| Without Pi Fortress | With Pi Fortress |
|---|---|
| The key files of the agent hold real keys. A stealer takes keys that work. | The key files hold placeholders (`pf_…`). A placeholder works nowhere else. |
| A hijacked agent can send a key to any address. | The gateway puts in the real key only for the service that owns it. A placeholder sent anywhere else gets a refusal and an alert. |
| A key in a known format leaves in a header, a URL or a body. | The gateway strips live keys in known formats before they leave. |
| Malware on the agent can turn off a local guard. | The gateway is a separate box on the network cable. The agent cannot turn it off. |
| An agent can connect to any site. | With [paranoid mode](faq.md#paranoid-mode), the agent can connect only to the sites on your allowlist. |

The risk model, with each attack that we tested and its result, is published with the source. To start, refer to [Getting started](getting_started.md).

## Sources

- CVEs per year: [cve.icu](https://cve.icu/) and Jerry Gamblin, [2025 CVE data review](https://jerrygamblin.com/2026/01/01/2025-cve-data-review/).
- GitGuardian, *The State of Secrets Sprawl 2026*, as reported by [The Hacker News](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html), March 2026. Each bar uses the value of its own edition, and a later edition can revise an earlier count. The 2022 to 2024 values are from the [2024](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2024/) and [2025](https://gitguardian.com/state-of-secrets-sprawl-report-2025) editions.
- GitGuardian, [The Nx s1ngularity attack: inside the credential leak](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/).
- BleepingComputer, [Shai-Hulud 2.0 npm malware attack exposed up to 400,000 dev secrets](https://www.bleepingcomputer.com/news/security/shai-hulud-20-npm-malware-attack-exposed-up-to-400-000-dev-secrets/).
- The Hacker News, [Attacker hijacks AI coding assistant](https://thehackernews.com/2026/09/attacker-hijacks-ai-coding-assistant.html), September 2026.
- The Hacker News, [Autonomous AI agents compromise thousands of credentials in under six hours](https://thehackernews.com/2026/09/autonomous-ai-agents-compromise.html), September 2026.
