# Hall of fame

Confirmed bypasses of the fence, from the capture-the-key challenge
([`challenge_rules.md`](challenge_rules.md)) and from reports under [`SECURITY.md`](../SECURITY.md). We credit other confirmed
security bugs in `SECURITY.md`.

We list a report when all of these conditions are true:

1. it is in scope under `challenge_rules.md`;
2. we reproduced it from a shell in an unmodified agent VM, against an
   unmodified gateway (the cloud lab or a Pi) on a published version;
3. it is the first report of its root cause;
4. its fix commit has landed, after a fuzz corpus entry and a regression
   test for it.

The date is when the report arrived. The handle is the one that the reporter
selected. We list anonymous reports as `anonymous`. The class is one of these:
`sni-host`, `smuggling`, `chunked-trailer`, `websocket`, `alpn`,
`dns-rebinding`, `direct-ip`, `doh`, `ipv6`, `claim-endpoint`,
`enrolment`, `fence-rce`, `other`.

| Date | Handle | Class | Fix commit |
|---|---|---|---|
