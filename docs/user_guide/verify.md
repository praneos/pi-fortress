<!-- How to verify the source by hand: the project key, a signed stable tag, a rebuild. -->
# Verify the source

Pi Fortress has no binary releases yet. Release builds start at v1, when
the project is stable. Until then, you build `pf` from the latest stable
tag ([Pi setup](pi_setup.md), step 6).

The project signs each stable tag with an SSH key. This page gives the
key and the commands to verify a tag before you build it.

## The project key

Save this line as `~/pi-fortress.allowed_signers`:

```
release@pi-fortress namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKVK/2pcp/J483O0Q/NvHVZr6jAR3uzMQfTabUh5B96R
```

The fingerprint of this key is
`SHA256:N8NU9P+r5dUez4Ki7wRFicKCiQRUwEx9lft7bC3Wx+w`. A good
`git verify-tag` prints it.

Get the key from this page. Never get it from the clone. A key that
comes with the source proves nothing.

Keep the file outside the clone. The build refuses a tree with files
that git does not track.

## Verify a stable tag

In the clone, find the newest stable tag:

```
git fetch --tags
git tag -l 'v*' --sort=-v:refname | head -1
```

Verify that tag. This example uses `v0.1.6`:

```
git -c gpg.ssh.allowedSignersFile="$HOME/pi-fortress.allowed_signers" verify-tag v0.1.6
```

The command must print this line:

```
Good "git" signature for release@pi-fortress with ED25519 key SHA256:N8NU9P+r5dUez4Ki7wRFicKCiQRUwEx9lft7bC3Wx+w
```

If it prints a different result, do not build that tag. Then run
`git checkout v0.1.6` and build.

The signature covers the tag and the commit that it names. Thus it
covers all the source at that commit. A commit on `main` that has no
stable tag has no signature from the project.

## Rebuild it yourself

Builds are reproducible. Two builds of the same tag make identical
bytes. Thus you can build a tag two times, on two machines, and compare
the `SHA256SUMS` files. The procedure, and how the project keeps and
rotates the key, are published with the source.

## Release downloads (from v1)

From v1, the project publishes signed release downloads. The same key
signs them, in the namespace `pi-fortress-dist`. This page will then
give the steps to verify a download.
