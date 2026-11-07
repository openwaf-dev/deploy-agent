# Contributing

Thanks for helping. Issues and pull requests are welcome in English or Spanish.

## Before you start

- **Security problems.** Send them to security@openwaf.dev or through GitHub's private vulnerability reporting.
  Never use a public issue ([SECURITY.md](SECURITY.md)).
- **Larger changes.** For anything larger than a small fix, open an issue first so that we can agree on the approach.
- **Protocol changes.** The protocol ([PROTOCOL.md](PROTOCOL.md)) must stay compatible both ways. A new message kind,
  operation or field must be optional, and must be announced as a feature when the control plane needs to know that the
  agent understands it.

## Checks

Run these before opening a pull request:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
sh -n install.sh
scripts/leak-guard.sh
```

Changes to deployments, the router or the firewall also need the end-to-end tests. They run against a throwaway Docker
Engine; the module documentation of `crates/deploy-agent/src/e2e.rs` explains how.

## How changes ship

OpenWAF maintains the agent together with the control plane, and this repository is exported from there. A merged
pull request here is applied there and comes back in the next export, as part of a release built by
[release.yml](.github/workflows/release.yml).

## Commits and sign-off

- Keep one logical change per pull request.
- Write a commit message that says what changes and why.
- Add tests for behaviour you add or fix.

Every commit must carry a Developer Certificate of Origin sign-off (<https://developercertificate.org>). It certifies
that you wrote the change or otherwise have the right to submit it under the project's license. `git commit -s` adds
the sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

Contributions are licensed under the Apache License 2.0 ([LICENSE](LICENSE)).
