# standalone/ — Phase 3 (standalone mode), preparation

The standalone end of the PoE suite: a sealed, Debian-derived OS
image that runs the full node service on bare metal, per the
adopted OS model. **Status: image built and boot-tested
(2026-11-18)** — see README correction 33 and
`~/workspace/poe-standalone-build/BUILD_REPORT.md`. The image
boots clean and performs its first-boot ceremony; two
defects are open (the node service does not reach readiness
in the guest, and systemd-networkd/resolved fail there).
No update key exists (the trust store ships empty), and the
profile is testnet until the owners open the mainnet gates.

The preparation document — image architecture, A/B updates and
the signed-manifest rules, the owners' 2-of-3 offline update-key
ceremony specification, the secure-element vault scoping, and the
five-flag conformance checklist — is
`PHASE3_PREPARATION.md` in the build workspace
(`~/workspace/poe-build-2026-11-11/`), summarized by the scope
document's Phase 3 section.

Layout:

- `image/` — partition layout, build recipe outline, and the
  update manifest's example.
- `trust/` — where the owners' update verification keys land at
  the signing ceremony. The repo carries none, by design.
- `systemd/` — the system unit for the node service in
  standalone mode (the system-mode counterpart of the app-mode
  user unit `poe-node service-unit` prints).
- `config/` — the device-local configuration surface.
