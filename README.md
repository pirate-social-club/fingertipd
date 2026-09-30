# fingertipd

`fingertipd` is the Linux HNS/DANE sidecar for Freedom Browser. It starts a
pinned `hnsd`, exposes letsdane's HTTP CONNECT proxy on an ephemeral loopback
port, persists a profile-local CA, and reports lifecycle telemetry as JSON
lines on stdout.

The normative browser/daemon interface is
[`docs/hns-daemon-contract.md`](https://github.com/pirate-social-club/freedom-browser/blob/resync/hns-binaries/docs/hns-daemon-contract.md).

## Development

```sh
go test ./...
go build ./...
```

The daemon requires `-data-dir` and `-hnsd-path`. DNS listeners default to
`127.0.0.1:15349` and `127.0.0.1:15350`, and every listener is required to be
loopback-only.

Hermetic tests may pass `-hnsd-seed 127.0.0.1:<port>` to connect the spawned
compile-time-regtest hnsd to their local hsd fixture. The flag is optional,
accepts loopback addresses only, and is omitted by every production launch.

## Address validation

The HNS sidecar requires authenticated responses for every requested address
family before opening an upstream connection. An authenticated empty AAAA
answer is acceptable alongside an authenticated A address. A failed or
unauthenticated answer in either family rejects the entire lookup, regardless
of completion order. Authenticated absence in every family is also rejected.
The loopback hnsd stub supplies the authentication result; the helper does not
trust an external resolver's AD flag.

DNSSEC is required for every HNS navigation, including plain HTTP. Unsigned
HNS zones are not supported. HTTPS additionally retains its validated DANE
requirement. This is the workspace_owner's explicit policy decision of
2026-09-30; ordinary browser HTTPS uses its normal route.

Failed validation, unvalidated answers and DNS errors such as SERVFAIL whose
validation status cannot be distinguished are terminal. Socket-level timeouts
and refused connections remain eligible for the explicitly configured
validating DoH fallback. Both local address families are checked before a
transport failure can retry elsewhere, so a validation failure in the other
family cannot be hidden. Caller cancellation does not retry. The fallback also
requires every family to validate or prove absence, and its returned addresses
must be authenticated. This does not activate DoH or implement delegated-zone
validation; the optional fallback remains off by default and limited to its
existing controlled top-level validation scope.

## Pinned dependencies

- `buffrr/letsdane` v0.6.1
- `handshake-org/hnsd` v2.0.0 (release workflow input)

The release workflow produces the Linux x64 production archive and its
`SHA256SUMS` trust manifest. It also produces a separately named, test-only
`hnsd-regtest-linux-x64.tar.gz` archive with an independent
`TEST_SHA256SUMS` manifest. The regtest binary is compiled from the same pinned
hnsd commit with `--with-network=regtest`; it is a hermetic-test fixture and is
never part of the production browser fetch allowlist.

The daemon is MIT-licensed. Its pinned letsdane dependency is Apache-2.0 and
the separately packaged hnsd binary is MIT-licensed; release archives retain
their upstream notices.
