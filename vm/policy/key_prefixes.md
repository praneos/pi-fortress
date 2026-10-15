# Common live-token prefixes (and lengths)

Detection should use **prefix + charset + length**, not the prefix alone.
GitHub tells issuers the same thing (unique prefix, high entropy, optional
32-bit checksum). A bare `sk-` causes false positives.

This file gives the reasons for `vm/policy/key_prefixes.rules`. The fence
loads the `.rules` file (`internal/fence/tokens.go`). The strip
shipped. If a value matches one of these on an origin server that is not permitted to
carry that kind, the fence replaces the value with the strip marker and logs it. Edit the
`.rules` file. This file records why each row has its shape.

## How GitHub automates this

This is not only a trick from a blog. It is an official pipeline:

1. **Partner program** — the issuer sends an email to `secret-scanning@github.com` with
   a token *name* and a **precise regex**. The advice from GitHub: unique prefix,
   high-entropy body, **32-bit checksum** if possible.
   https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partner-program
2. **Scan** public repos + public npm by default; private repos if GHAS /
   secret scanning is on.
3. **Match → webhook** — GitHub POSTs `{token, type, url, source}` to the
   issuer. The issuer can revoke the token. GitHub signs with ECDSA. The keys are at
   `GET https://api.github.com/meta/public_keys/secret_scanning`.
4. **Validity check** (some patterns) — GitHub sends a request to the issuer API
   (200 vs 401). That is *live* confirmation, not only a regex.
5. **Push protection** — GitHub blocks `git push` if the payload looks like a
   current, high-confidence token version. Older/legacy shapes are often
   scan-only, so that they do not block commits.
6. **Custom patterns** — orgs add their own regex (before/after
   boundaries + length). The engine is the same.

Useful writeups:

- GitHub Changelog (2021): GitHub *added* the `ghp_` / `gho_` / … prefixes
  *so that secret scanning could work*. The length of those bodies stayed 36.
  But GitHub told integrators to accept up to 255 later.
  https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available
- Semgrep (2025), “Prefixed Secrets That Tried to Get Away”: scanners
  that use `ghp_[A-Za-z0-9]{36,255}` ignore the fixed length. This
  increases FPs. Use the exact length for each token *version*.
  https://semgrep.dev/blog/2025/secrets-story-and-prefixed-secrets
- Pattern catalog: https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns

The tokens of GitHub also have a **checksum** in the body. A shape match
is necessary, but not sufficient. GitHub can reject `ghp_` + 36 chars with a
bad CRC offline. We should not claim to implement that CRC again unless
we have a published algorithm.

## Prefix + length (use these)

Lengths are the **body after the prefix**, unless the table says total. In
`key_prefixes.rules`, each length is a minimum (`{36,}`), not an exact
count. For the reason, see "What we match" below.

| Prefix | Body | Total | Notes |
|---|---:|---:|---|
| `ghp_` | `[A-Za-z0-9]{36}` | 40 | classic PAT. **Fixed.** |
| `gho_` `ghu_` `ghs_` `ghr_` | `{36}` | 40 | OAuth / app tokens. **Fixed** today; GitHub said they may grow. |
| `github_pat_` | `{22}_{59}` | 93 | fine-grained. **Fixed** shape (underscore in the middle). |
| `glpat-` | often `{20}` | ~26 | GitLab PAT. Treat as fixed-ish; confirm if we gate GitLab. |
| `npm_` | `{36}` | 40 | npm access token. **Fixed** in current docs. |
| `AKIA` | `[A-Z0-9]{16}` | 20 | AWS *access key id*. **Fixed.** Secret key has **no** prefix. |
| `ASIA` | `{16}` | 20 | AWS STS temporary id. **Fixed.** |
| `AIza` | `[0-9A-Za-z_-]{35}` | 39 | Google API key. **Fixed.** |
| `hf_` | `[A-Za-z]{34}` | 37 | Hugging Face. **Fixed** in gitleaks. |
| `sk-ant-api03-` | `{93}AA` | 108 | Anthropic user key. **Fixed**; must end in `AA`. |
| `sk-ant-admin01-` | `{93}AA`? | ~108 | Anthropic admin. Length not confirmed; matched as the prefix and 20 or more (`anthropic_admin`). |
| `sk-ant-oat01-` | high-entropy rest | ~100+ | Claude Code OAuth **access**. Length not published as fixed; prefix is the match. |
| `sk-ant-ort01-` | high-entropy rest | ~100+ | Claude Code OAuth **refresh**. Same. |
| `sk_live_` / `sk_test_` / `rk_live_` | often `{24}` | ~32 | Stripe. **Mostly fixed**; some scanners use `{24,}`. |
| `SG.` | high-entropy rest | varies | SendGrid. Prefix strong; length looser. |
| `xoxb-` etc. | `digits-digits-alnum` | varies | Slack. **Not** a single length. |

### Not fixed — do not use a single length

| Prefix | Reality |
|---|---|
| `sk-` (OpenAI legacy) | was `{48}` after prefix; **no longer issued**. |
| `sk-proj-`, `sk-svcacct-`, `sk-admin-`, `sk-None-` | started ~48 body, later **~156**, often around a literal `T3BlbkFJ` (base64 `"OpenAI"`). Matched on the prefix and 40 or more token bytes (`openai_proj` and the rest), not on one length and not on the marker, so a key without it still strips. |
| `xai-` | 80 of `[A-Za-z0-9_]` in the keys seen so far, not documented as fixed. Matched as 60 or more (`xai`), which clears model and package names such as `xai-grok-4`. |
| `gsk_` (Groq) | prefix-only until we pin a length from a live key. |
| JWT `eyJ` | variable. High FP. |

## What we match

1. Longest prefix first (`sk-ant-api03-` before `sk-ant-` before `sk-`).
2. Exact charset, and the length from the table as a **minimum**: `{36,}`, not
   `{36}`. No closing `\b`. The body continues to its natural end: the first
   byte outside the charset of the rule. Thus, the fence strips the full key and no
   tail of it stays.
3. A distinctive prefix (`ghp_`, `github_pat_`, `sk-ant-`, `xai-`, `glpat-`,
   `hf_`) has no condition before it. It matches at all positions, glued to a
   word or not. A prefix that can occur inside
   ordinary words keeps a leading `\b` (`sk-`, `sk_live_`, `AIza`,
   `npm_`: task-, flask-admin-, base64, pnpm_). The fence reads that
   `\b` as "not after a letter, digit or `_`, unless that byte ends an
   escape": `\n \t \r \b \f`, `\xXX`, `\uXXXX` or `%XX`. The fence
   matches the escape but does not strip it. Thus, the JSON stays valid and the URL stays well
   formed (`internal/fence` `leadExpr`).
4. AWS issues key ids in upper case. Each AWS rule is two lines under
   one name:
   - Upper case (`(?-i:...)`), to the natural end, at all start positions.
   - Any case, but only at the exact length with a boundary on each side.

   Thus, the fence still catches an id with flipped case. A mixed-case or lower-case
   identifier or name (`AsiaPacificSoutheastRegion`,
   `asiapacificcommunications.com`) is not an id. The same rules run on
   DNS names in pf dns and in the SNI check of the broker. These see names in any
   case.
5. Do **not** call vendor APIs from the Pi to “validate” (that is the partner
   webhook of GitHub). Prefix+length is sufficient to *drop/strip* an exfil
   header. Validity is optional later.

Why a minimum, against the advice of Semgrep above: a strip rule is not a
scanner. Users disable a scanner that reports too much. A strip rule
that matches too little forwards the key. A rule with a fixed length and a
`\b` on each side, such as `\bghp_[A-Za-z0-9]{36}\b`, matches none of these:

- A key one word byte longer: a longer issue of the same token, a key
  glued to the next word, or a key with one byte added.
- A key directly after a JSON `\n` or a `%20` in a query. Reason: the byte
  before the key is a letter or a digit.

`anthropic` keeps its `AA` and takes what follows it:
`sk-ant-api03-[A-Za-z0-9_-]{93,}AA[A-Za-z0-9_-]*`. `anthropic_admin` is
the prefix and 20 or more bytes, like the OAuth tokens. Its length is
not published, so it does not require the `AA`. It has no kind. Thus, the fence
strips it at all origin servers, `api.anthropic.com` included.

Measured on 2026-10-06 against 246 MB of ordinary text (the Go source
tree and its testdata, vendored modules, `/usr/share/doc`, a 104,000
word dictionary, these docs): 4 matches with the fixed-length rules and 4
with these rules.
All of them are key-shaped on purpose (a docs placeholder, an AWS example id).

A second test used 200,000 synthetic identifiers and domain names, in camel,
lower, upper, snake and kebab case. Half of them start with
a near-miss (`asia`, `AKIA`, `task-`, `flask-admin-`, `pnpm_`, `kaiza`).
The results:

- 1,232 before (exact-length AWS hits).
- 18,474 with the minimum alone.
- 2,899 now.

The remainder is
the same exact-length hits plus upper-case runs such as
`ASIABANKBOOKSUTTERED...`. The upper-case AWS rule takes these as an id.

Machine list without lengths: `key_prefixes.txt` (longest-first).
