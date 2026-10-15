# Git push allowlist

`vm/policy/git_push.allow` names the repos that the agent segment can push to
over git smart HTTP. **If the file is empty or missing, the broker refuses all pushes** (the default).

## File

```
github.com acme/widget      one repo; ".git" in the file or the request is ignored
github.com acme/*           every repo one segment below acme
gitlab.com grp/sub/repo     a subgroup path is the repo
```

- The host is exact and lowercased. The owner/repo is case-insensitive.
  Segments are `[a-z0-9._-]`, never `.`/`..`. There are at least two segments.
  `*` is permitted only as the full last segment, for one level:
  `grp/*` does not cover `grp/sub/repo`.
- A malformed line fails `pf compile`, so `pf apply` stops. The broker
  also refuses to start with a malformed line.
- `PI_OWNED`: `make pi-ship` seeds the file. It never overwrites it. There
  is no TUI screen yet. On the Pi, edit `/opt/pi-fortress/vm/policy/git_push.allow`.
  Then run `sudo pf apply`. It copies the file over `/etc/pi-fortress/`. The
  next apply reverts an edit that you make only in `/etc`.
  A change restarts the fence. `pf status` prints `git_push.allow: N repos`.

## What is refused

The refusal applies to all hosts. It covers the two halves of a push.
It does not change `git-upload-pack` (clone, fetch):

```
GET  /<repo>[.git]/info/refs?service=git-receive-pack   git fails before packing
POST /<repo>[.git]/git-receive-pack
```

`broker.gitPushRefuse` runs after the blocklist and paranoid checks.
It runs before the 100-continue, so the broker never reads a refused pack.
A push goes through only if the list has its repo for the Host. If the SNI
is set, the list must also have the repo for the SNI.
Target parsing (`fence.GitPushTarget`) fails closed:

1. Hot path: one pass, one percent-decode level, zero allocations. If there is no
   `receive-pack` and no second encoding level, the request is not a push.
2. Push-shaped (fully decoded, at most 4 rounds, lowercased): the path
   has `receive-pack` and the method is not GET/HEAD. Or, `receive-pack`
   follows the last `refs` of the path, in the path or query.
3. A push-shaped request must be clean:
   - The raw path has only `[A-Za-z0-9._-/]` (no `%`, `;`, `\`).
   - It has no empty/`.`/`..` segment (no `//`, no trailing `/`).
   - It ends with `git-receive-pack` or `info/refs`.

   The parser cuts an absolute-form target to its path.
4. Push-shaped and not clean: the broker refuses it, whatever the list contains.

## Refusal

The broker sends the uniform 503 (`Retry-After: 60`, connection closed).
It writes one strip.jsonl row with these fields:

- `ev=substitution_refused`, `rule=refused:git_push_not_allowed`,
  `cause`, `host`, `sni`, `client_ip`.
- Then `where=target` with `repo=owner/repo`, or `where=target_ambiguous`
  with `repo=` the raw path (256 bytes).

`repo` is the new last field. The refusal is not an alert.

## Not covered

The list controls only the push protocol of git. The token scope is the real
control. Give the slot a fine-grained token for the listed repos.

- `api.github.com` writes: contents API, git data API,
  `createCommitOnBranch`, merges, releases.
- Gists: `gist.github.com/<id>.git` is one segment. Thus, you cannot list it, and
  the broker always refuses it. The list does not control the gists API.
- Git LFS uploads (`info/lfs/objects/batch`, then storage PUTs).
- SSH push: the gateway drops TCP 22 unless [ssh_allow](ssh_allow.md) lists
  it. In that case, this list does not apply.
- False positives:
  - A non-GET/HEAD path that contains `receive-pack` but is not a clean
    push (a repo named `receive-pack.git`).
  - Five or more encoding levels on a candidate target.
- TUI editing: follow-up.
