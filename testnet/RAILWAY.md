# Run a public PoE node on Railway

The launch operator's bootstrap nodes sit behind NAT and cannot be
reached from the public internet (see TESTNET.md). A node on
Railway fixes that: Railway's **TCP proxy** gives the service a
public hostname and port that forward straight to the node's
libp2p listener, and a **Volume** keeps its state across deploys.
One reachable node is enough — the NATed bootstraps dial *it*,
and gossip flows both ways over that connection.

What you need: a Railway account on a paid plan (an always-on
service with ~2 GB RAM runs roughly $20–30/month at Railway's
usage prices — the included plan credit does not cover it).

## Deploy

1. **New Project → Deploy from GitHub repo** → pick
   `hivemusedev-cloud/Proof-of-Existence`. Railway detects the
   `Dockerfile` at the repo root and builds it (first build of the
   Rust workspace takes a while — 10–20 minutes is normal).
2. **Add a Volume**: open the service → *Settings* → *Volumes* →
   mount path **`/data`**, size **1 GB**. (If the service already
   deployed once without it, it redeploys with the volume attached
   — fine, nothing is lost, there was no state yet.)
3. **Add the TCP proxy**: service → *Settings* → *Networking* →
   *TCP Proxy* → application port **`41001`**. Railway shows a
   public address like `<name>.proxy.rlwy.net:<port>` — write it
   down, it is this node's public face.
4. **Do not set any variables yet.** On first boot the node creates
   its identity, prints its `MACHINE`, `LISTEN` and `START` lines,
   and waits. (Startup is quiet for the first minutes — deriving
   the XMSS vote key is a few minutes of CPU on every start. That
   pause is normal, on every host.)
5. From the deploy logs, send the operator (whoever runs the
   existing bootstraps) two things:
   - the **`LISTEN /ip4/.../p2p/<peer id>`** line, and
   - the **TCP proxy address** from step 3.
6. The operator hands you back a **bundle URL** (a fresh epoch
   bundle, the chain's own checkpoint file). Set it as a service
   variable named **`POE_BUNDLE_URL`** and let the service restart.
   The entrypoint downloads the bundle, syncs the node from it,
   and the node joins the running chain in-protocol. A bundle
   stays usable for ~6.8 hours (the nodes' served-history
   retention), so there is no split-second timing — but don't
   leave it for days.
7. The operator points a bootstrap at your node
   (`--peer /dns4/<proxy host>/tcp/<proxy port>/p2p/<peer id>`);
   within a few epochs your node's closes should print the same
   roots as everyone else's. You are a bootstrap now — the
   operator lists your address in TESTNET.md.

## Notes

- **State is the volume.** Keys, store and snapshots all live in
  `/data`. Delete the volume and the node is a brand-new machine
  (its old machine stays registered as a ghost — harmless, see
  TESTNET.md). Redeploys and restarts resume from the volume.
- **Re-sync lever:** to move the node to a newer bundle later,
  just change `POE_BUNDLE_URL` to a fresh URL and restart — the
  entrypoint replaces the chain state and keeps the identity.
  Remove the variable entirely to go back to plain resume.
- **No inbound HTTP is used.** The service speaks only libp2p/TCP
  on 41001 through the proxy. Railway's HTTP domain is not needed.
- Memory: give the service room for ~2 GB; much less and the
  kernel will kill it mid-round, which the chain experiences as a
  lost voter (see the liveness note in TESTNET.md).
