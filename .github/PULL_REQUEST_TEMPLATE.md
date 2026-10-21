## What and why

<!-- A short description of the change and the reason. Link the issue it closes, if any. -->

## Checks

- [ ] I ran: `cargo test`, `cargo fmt --all --check`, `cargo clippy --all-targets`; for DLL changes also `cargo xtask build-dll` in the main repository
- [ ] README or the main repository's docs updated if behaviour changed
- [ ] No game files, official-server captures, `Client.txt` excerpts, secrets or personal data in the change
- [ ] Nothing in the change sends, alters or injects anything on official servers (the read-only rule)
- [ ] I did not copy code from AGPL reference projects (KiwiNet, exileSniffer, LibGGPK3)
