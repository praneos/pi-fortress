# Verify a download

The signed release bundles are published with the public release. This
page goes on the website with the first release.

`install.sh` and `pf upgrade` do these checks before they install
anything. They:

- Verify the signed `SHA256SUMS`.
- Make sure that the bundle is the bundle that `SHA256SUMS` lists for
  the tag that you asked for and for the architecture of your box.
- Check the signature of the bundle.

You need this page only to check a download manually, or before you
trust `install.sh` itself.

## The release key

The release key is published on this page with the first release. Save its line as `allowed_signers`.

Get the key from this page. Never get it from the download folder. A
key that comes with the files proves nothing.

The release notes on the
release page show
the same line a second time. Compare the two lines before you trust
either of them. `install.sh` also contains the same key, as
`PF_SIGNER_PUBKEY`.

## Check a release

Each release on the release
page has `SHA256SUMS` and `SHA256SUMS.sig`. In the download folder, run:

```
ssh-keygen -Y verify -f allowed_signers -I release@pi-fortress -n pi-fortress-dist -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

Both must pass.

## Check one bundle

Each `pf-bundle-<version>-<arch>.tar` also has its own `.sig` file.
`install.sh` and `pf upgrade` also check this signature.

The signature proves that the release key signed these bytes. It does
not prove the release or the architecture of the bytes. An older bundle
also passes this check. Thus, also do these checks:

- Check `SHA256SUMS`, as in the section above.
- Make sure that the file name has the tag and the architecture that
  you want.

```
ssh-keygen -Y verify -f allowed_signers -I release@pi-fortress -n pi-fortress-dist -s pf-bundle-v1.2.3-arm64.tar.sig < pf-bundle-v1.2.3-arm64.tar
```

## Rebuild it yourself

Builds are reproducible. Two builds of the same tag make identical
bytes. Thus you can build a tag again from the source and compare it
with the published `SHA256SUMS`. The procedure, and how the project keeps
and rotates the key, are published with the source.
