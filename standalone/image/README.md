# The standalone image — layout and build outline

Preparation only: this is the layout the Phase 3 build will
produce, from the preparation document (§1, §3).

## Partitions

| partition | content | mount |
| --- | --- | --- |
| boot | bootloader + slot selection | /boot (ro) |
| rootfs A | the sealed system, slot A | / (ro, when active) |
| rootfs B | the sealed system, slot B | / (ro, when active) |
| data | node data: ledger store, finstate, bundles, certificates, wallet | /data (rw, eMMC/NVMe — flag 2) |
| recovery | minimal recovery system | SD media only, never ledger state |

## Build outline

1. Debian bookworm base, package set pinned by the recipe (the
   node binary, the update agent, the network profile of flag 4;
   no Zigbee stack, no remote-administration listener).
2. The node binary and trust store (owner verification keys,
   from `../trust/` at ceremony time) are baked into the rootfs;
   no identity is baked in — first boot is the identity ceremony.
3. The rootfs is hashed (SHA-256) and the hash goes into the
   update manifest (`manifest.example.json`); the image is
   published unsigned — the manifest carries the signatures.

## Update rule, in one paragraph

An update writes the inactive slot, having first verified the
manifest (≥ 2 of 3 owner signatures, counter strictly greater
than the last applied) and the image hash. The bootloader trial-
boots the new slot once; the node answering `status` on its
control endpoint within the boot deadline, at an epoch no older
than the pre-update one, marks the slot good. Anything else
returns to the previous slot. Full rules: preparation document
§3.
