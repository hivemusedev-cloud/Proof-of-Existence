# trust/ — the owners' update verification keys

At the signing ceremony (preparation document §4), the build
side receives the three owner update **public** keys — with
key_ids and fingerprints the owners confirm — and bakes them
into the image trust store from this directory.

This directory is empty in the repository, and must stay empty
of anything but public keys:

- No secret key is ever placed here, on the build machine, or on
  any online machine. Owner secret keys exist only on the
  keyholders' own air-gapped machines.
- A key file appearing here without the ceremony's confirmation
  is not a trust root; the fingerprints are confirmed by the
  owners out of band before any image is built with them.
