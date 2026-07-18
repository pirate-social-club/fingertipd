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
