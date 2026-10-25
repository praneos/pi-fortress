# Signed ship

This is the developer loop. It ships your own build from a desktop to a
Pi. An install from source at a stable tag uses `install.sh` and
`pf upgrade` instead (`gateway_install.md`). From v1, a release install
does the same. Below, `<user>` is your login user on the Pi
(`PI_USER` for `make`).

Before: `make pi-ship` was rsync as your login user, plus `sudo pf apply`
on passwordless sudo. Thus the login key of the desktop was root on the
gateway.

Now:

- `make pi-ship` signs a bundle and uploads it as `pfship`. The key of
  `pfship` can write only one directory.
- Root installs only what the release key signed.
- sudo asks for a password.

`make pi-ship-sudo` keeps the old loop. It keeps the `.pf-ship-version`
of the tree through its `--delete`. It runs `pf ship confirm` before its
`pf apply`. Thus a confirm that is still armed from an earlier signed
ship cannot swap an older `.prev` back over the push.

## Flow

1. Desktop:
   - `pi-bundle` builds arm64 `pf`.
   - `pi-bundle` stages the tracked and untracked-but-not-ignored files
     of the working tree, plus that `pf` at `vm/pi/pf`. Uncommitted
     edits ship. `.cache/`, `build/`, `bin/`, and other ignored files
     do not ship.
   - `pf ship bundle` tars the stage with the same keep and seed rules
     as `pi-sync`. The first entry is `pf-ship.json`. It has the version
     (build time, unix seconds), the git sha (`-dirty` if uncommitted),
     and the size, sha256, and exec bit of each file.
   - `pi-sign` runs `ssh-keygen -Y sign -n pi-fortress-release`.
   - `pi-ship` rsyncs the bundle, then the `.sig`.
2. Pi: when `/var/lib/pi-fortress/incoming` is not empty,
   `pi-fortress-ship.path` starts `pi-fortress-ship.service`
   (`pf ship install`, root). The service waits for both files with no
   rsync temp file. It stops the wait after 60 s with no change.
3. The service copies both files to a root 0700 work dir: O_NOFOLLOW,
   regular files only, size-capped. It reads nothing from `incoming`
   again.
4. `ssh-keygen -Y verify -I release -n pi-fortress-release` checks
   against `/etc/pi-fortress/allowed_signers`. A missing, non-root, or
   group/world-writable file refuses everything. A file with a key line
   that does not have `namespaces="pi-fortress-release"` as its one
   namespaces option also refuses everything. `provision.sh` does not
   install such a file from `PF_ALLOWED_SIGNERS`.
5. Extraction:
   - The manifest must be first, and its version must be above
     `/var/lib/pi-fortress/ship.version`. If one of these two rules
     fails, the service refuses the ship before it writes anything.
   - Every entry must be a directory or a regular file listed once,
     with a matching size and sha256.
   - Refused: links, devices, fifos, absolute paths, `..`, `./`,
     unlisted or missing files.
   - Modes come from the manifest (0644/0755), never from the header.
6. The service stages to `/opt/pi-fortress.new`. It transfers the keep
   paths from the live tree: `generated/`, `alert.url`, and the
   operator-owned lists. A symlink in these paths refuses the ship.
   Under the apply lock, it swaps (renameat2 exchange). It keeps the old
   tree as `/opt/pi-fortress.prev`.
7. It runs `pf apply`. If apply fails:
   - `.prev` is swapped back.
   - The refused tree goes to `/opt/pi-fortress.failed`.
   - apply runs again.

   `ship.version` is written after the swap and before that apply. The
   rollback restores the old floor together with the old tree. Thus a
   bundle that fails apply does not raise the floor.

   The swap also puts a copy of the floor inside the tree:
   `.pf-ship-version`. Thus a power cut between the swap and the floor
   write no longer leaves a window. The next run takes the higher of the
   file and the stamp. It sees the tree that outran its file, and writes
   the file back.
8. Each run empties `incoming`. Each attempt appends a row to
   `/var/log/pi-fortress/ship.jsonl`. The row is one of:
   `ok`, `busy`, `incoming`, `incomplete`, `bad_upload`, `bad_sig`,
   `version_file`, `rollback`, `bad_bundle`, `swap`, `apply_failed`,
   `post_upgrade`, `confirm`, `deadman`, `deadman_failed`,
   `rollback_failed`, or `error` for all other failures.
   Each row other than `ok` or `confirm` posts to the alert webhook.
   `pf doctor` shows the last row (rung `ship`). It warns on
   `NOPASSWD: ALL` (rung `sudo`).

## Confirm or revert

After a successful apply, `pf ship install` runs
`pf doctor --post-upgrade`. This checks:

- The required units (`/var/lib/pi-fortress/units.required`). `apply.sh`
  writes this file. Thus this check never hardcodes a unit that is
  optional on some box.
- At the own resolver of each segment, `pi-fortress-block.test` is
  sinkholed and a public name resolves.
- The broker and engine sockets accept a connection.
- A DNS answer from `DNS_UPSTREAM` proves the default route and the
  uplink.

The doctor checks again for up to 90 s (`--settle`). A check that still
fails then rolls back immediately. It uses the same `.prev` path as a
failed apply (row `post_upgrade`). `pf ship install -post-upgrade-settle`
changes this window. It is for tests and labs only: on a real box, a
short window can roll back a good build whose units start slowly.

A passing check arms `/var/lib/pi-fortress/ship.pending` (`version`,
`prev_version`, a 10-minute `deadline`; `-confirm-deadline` or
`PF_SHIP_CONFIRM_DEADLINE` changes it). The design does not use a
`systemd-run` transient timer, because a reboot would lose that timer.
A reboot is the most frequent result of an upgrade.

`pi-fortress-ship-deadman.timer` (`OnBootSec=2min`,
`OnUnitActiveSec=1min`, `Persistent=true`) runs `pf ship deadman` every
minute and after every boot. If the deadline is past and nothing is
confirmed, deadman rolls back to `prev_version` in the same way as
`pf rollback` (row `deadman`).

- The pending file is removed only after the previous tree is live
  again.
- A rollback can fail because the TUI or a feed refresh holds the apply
  lock. Then deadman logs `deadman_failed` and keeps the file. The
  rollback is tried again the next minute.
- If there is no `.prev` to restore, a retry can do nothing. Then the
  file is cleared, and a `deadman` row records this.
- An unreadable or empty pending file (a crash mid-write; the file and
  its directory are fsynced) is an unconfirmed upgrade. On its next run,
  deadman reverts to the version that `.prev` carries, and it does not
  wait for a deadline. If `pf ship confirm` runs first, it clears the
  file, and deadman reverts nothing. If deadman also cannot read the
  version that `.prev` carries, it logs `deadman_failed` and keeps the
  file. It logs a new row, and sends the alert, only when the reason
  changes. To stop the retries, repair `.prev` or run `pf ship confirm`.

In other cases, `pf ship confirm` only removes the pending file and logs
`confirm`. At its end, `make pi-ship` tells you to run it.

A successful swap clears any pending file from an earlier upgrade,
because the swap overwrote its `.prev`. A swap that failed does not
clear it.

## Rollback and kept releases

Each successful install keeps `/var/lib/pi-fortress/releases/<version>/`.
This directory has:

- `bundle.tar`. The state-version guard (below) reads it only for the
  `state_max` of its manifest.
- `state.tar`.
- `release.json`.

The last three versions are kept. The oldest is pruned.

`state.tar` is a snapshot of `/etc/pi-fortress` and
`/var/lib/pi-fortress`, taken immediately before the own swap of that
version. Thus it shows the box as it was immediately before this
version took control. It does not include data that must never come
back from an old copy:

- The credential store (`broker/secrets.env` and its lock, staging
  files and `secrets.disabled`).
- The engine CA key.
- `mitm/`.
- `mullvad.conf` and `wireguard/`.
- Agent pastes.
- Claims.
- The signer files (`allowed_signers`, `release-signers`,
  `pfship.pub`).
- The lab marker.
- Run counters and offsets.
- The own bookkeeping of ship (`ship.version`, `ship.pending`,
  `state.version`, `releases/`, `incoming/`, `ship-work/`, `install*/`,
  `upgrade/`).

A restore:

- Skips the same paths, even when an older snapshot carries them.
- Refuses to write through a symlink anywhere under `/etc/pi-fortress`
  or `/var/lib/pi-fortress`.
- Stages each file next to its target, then renames it over the target.

A daemon can write to some of those directories (pf-dns owns its
state). Thus the check cannot be by path. A directory swapped for a
symlink between the check and the write would redirect a root write.

Each root is opened one time (`os.Root`). Each directory below it is:

1. Reached from the descriptor of the directory above.
2. Lstat'ed.
3. Opened.
4. Kept only if it is the directory just checked.

The stage is created `O_EXCL` in that descriptor. It gets its mode and
the owner of the replaced file on its own descriptor (`fchmod`,
`fchown`). Then it is renamed over the target in that directory.

A name swapped after this is not on any path that the restore uses. A
link swapped in at the target is replaced, never followed. The list
mirror below works in the same way. `release.json` records which
version was live when `state.tar` was taken.

`pf rollback` swaps `.prev` back in, applies again, and lowers the
floor to the version of `.prev`, with a `rollback` row. It needs no
signature, because the floor only stops a *remote* replay through
`pfship`. Root on the box can already do anything.

- If the swap could not occur (apply lock held), `pf rollback` logs
  `rollback_failed`, leaves any pending confirm armed, and exits
  non-zero.
- If the tree went back but its re-apply or `--with-state` failed, it
  says so and exits non-zero.

Rollback goes back one version only, to `.prev`. There is no `--to`: it
is refused as a usage error. To move to a newer release, use
`pf upgrade -version`.

`--with-state` restores state before the re-apply. It uses the
`state.tar` that the current release took immediately before it
replaced `.prev`. This is the state that `.prev` ran with.
`--with-state` is refused at the start if that `state.tar` is missing,
or if it is recorded as taken over another version.

A rollback that moved the tree clears a pending confirm.

The lists of the operator (the `PI_OWNED` of the Makefile under
`vm/policy/`, `backup.PiOwned` in code) stay across a rollback, as they
stay across an upgrade. These operations exchange `.prev` back:

- `pf rollback`.
- The dead-man revert.
- The restore after a failed apply or post-upgrade doctor.

Immediately before `.prev` is exchanged back:

- Each list that the live tree has is copied over the list in `.prev`.
  The copy is staged next to it and renamed. The mode is kept. The copy
  never goes through a symlink. Each directory is reached by
  descriptor, as for `--with-state`.
- A list that the live tree does not have is removed from `.prev`.

Thus a change made after the upgrade stays as the operator left it. For
example: a revoked allowlist entry, a removed push repo, or an added
block.

If that mirror fails, nothing is swapped:

- `pf rollback` logs `rollback_failed` and exits non-zero.
- The dead-man logs `deadman_failed`, keeps `ship.pending`, and tries
  again the next minute.

A return with the older lists of `.prev` would silently allow again
what was revoked.

## State version

`/var/lib/pi-fortress/state.version` is an integer. It is currently 2.
Version 1 is older than the `secrets.expires` sidecar. Version 2 is the
format that carries it.

The manifest of each bundle declares `state_min`/`state_max`: the range
that its binary can read. A bundle from before this field is treated as
`state_max: 1`. Install writes `max(current, state_max)` and never
lowers it.

`pf rollback` to a version whose `state_max` is below the current state
version of the box refuses, unless `-force` says to do it anyway.
Reason: an older build would read `secrets.expires` as absent. That
would let an expired slot work again.

## Threats addressed

- Stolen login key: a login shell, but sudo needs a password.
- Stolen ship key: it can write `incoming` only, through rrsync. It
  gets no shell, no reads, and no port forwards.
- Tampered or unsigned bundle: `bad_sig` plus an alert.
- Replay of an older signed bundle (a downgrade to a known bug): `rollback`.
- Tar path tricks, and a swap of the upload during the check: steps 3 and 5.
- A bundle whose apply breaks the Pi: the previous tree is restored and applied again.

## Not addressed

- A compromised desktop that holds the release key. A key file on disk
  signs anything. Thus use `ed25519-sk`: each signature needs a touch.
  Malware can still swap the bundle immediately before that touch.
- The login password typed into a keylogged desktop, together with the login key.
- Root on the Pi by other means: console, SD card, a bug in a root service.
- The keep paths and operator-owned lists are the own copy of the Pi. They are not signed.
- A holder of the ship key can fill `/var` until the next run deletes
  the upload. The holder can also trigger alerts.
- Version is the desktop clock. A signed bundle with a far-future version blocks later ships until
  root edits `ship.version`.
- Public `pf` downloads: `release.md` (namespace `pi-fortress-dist`, so its signatures never verify here).

## Setup

Desktop:

```
ssh-keygen -t ed25519-sk -f ~/.ssh/pi_fortress_release -C pi-fortress-release   # no FIDO key: -t ed25519, with a passphrase
ssh-keygen -t ed25519 -f ~/.ssh/pi_fortress_ship -N '' -C pfship                 # not your login key
printf 'release namespaces="pi-fortress-release" %s\n' "$(cut -d' ' -f1,2 ~/.ssh/pi_fortress_release.pub)" >bin/allowed_signers
PI_IP=10.79.0.1 make pi-ship-sudo
scp ~/.ssh/pi_fortress_ship.pub bin/allowed_signers <user>@10.79.0.1:/tmp/
```

On the Pi, set a password first, while passwordless sudo still works:

```
sudo passwd <user>
sudo install -D -m 0644 /tmp/pi_fortress_ship.pub /etc/pi-fortress/pfship.pub
sudo PF_ALLOWED_SIGNERS=/tmp/allowed_signers PF_REMOVE_NOPASSWD=1 SRC=/opt/pi-fortress bash /opt/pi-fortress/vm/pi/provision.sh
```

The tail must not say `pfship gets no key` or `allowed_signers missing`.
It says `removed /etc/sudoers.d/...`, or it says why the file was left.
The removal occurs only when all of these are true:

- Every rule in the file is `user ALL=(ALL) NOPASSWD: ALL`.
- `passwd -S` shows `P`.
- `visudo -c` passes.
- `sudo -l -U` still shows `(ALL : ALL) ALL`.

If not, the file is restored. The original goes to
`/var/backups/pi-fortress-sudoers/`.

Keep a root shell open. Before you close it, test `sudo -k; sudo true`
in a new session. Then run `PI_IP=10.79.0.1 make pi-ship`. Make sure
that `tail -1 /var/log/pi-fortress/ship.jsonl` shows `"result":"ok"`.

`SIGN_KEY` signs ship bundles only. `make release` uses a separate key,
`DIST_KEY` (release.md). The namespaces also keep the signatures apart. After
a signed ship, root owns the tree. Thus `pi-sync` and `pi-provision`
fail.

## Recovery

- Sudo lost (no known password, or no group `sudo`): use the console,
  or put the SD card in the desktop. Copy
  `var/backups/pi-fortress-sudoers/<file>` back to `etc/sudoers.d/`
  with mode 0440 and owner root. If sudo was never restored, add
  `init=/bin/sh` to `cmdline.txt` on the boot partition. Then run
  `passwd <user>`.
- Release key lost: make a new key. Then put its line in
  `/etc/pi-fortress/allowed_signers` through `sudo` or the SD card.
- Stuck on a far-future version: the floor is in two places. To lower
  it, lower both:
  - `echo <unix-seconds> | sudo tee /var/lib/pi-fortress/ship.version`
  - `sudo rm /opt/pi-fortress/.pf-ship-version`

  The file alone is not sufficient. The live tree has its own copy, so
  that the removal of one file cannot reset the replay guard. That is
  the purpose of the copy. Do this only on a box that you hold. A
  lowered floor is what lets an older signed build install again.
- Pi broken after `apply_failed`: run `journalctl -u pi-fortress-ship -n 80`,
  and examine `/opt/pi-fortress.failed`. The live tree is the previous
  one. `make pi-ship-sudo` ships from the desktop.
- Nothing happens after an upload: run
  `systemctl status pi-fortress-ship.path pi-fortress-ship.service` and
  `sudo ls -la /var/lib/pi-fortress/incoming`.
  `sudo systemctl start pi-fortress-ship` runs the install one time.
