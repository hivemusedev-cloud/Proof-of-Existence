# config/ — device-local configuration

Everything a standalone device is configured with lives on the
device, on its data partition — there is no account, no remote
configuration, and no telemetry to configure. The surface, as
scoped by the preparation document:

- **Network profile** (flag 4): Ethernet primary; WiFi as a
  configured fallback. Credentials are entered on the device
  and never leave it.
- **Bundle source**: where the node fetches its sync bundles
  (a mirror URL or local media) — transport only; bundles and
  certificates are verified from their own evidence, so the
  source needs no trust.
- **Update source**: where manifests and slot images are
  fetched from (mirror, USB, LAN peer). Again transport only:
  the manifest's owner signatures are the trust (2-of-3,
  preparation document sections 3-4).

No file in this directory carries a default that reaches the
network on the user's behalf before they set it.
