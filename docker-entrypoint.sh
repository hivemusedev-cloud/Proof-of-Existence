#!/bin/sh
# PoE testnet node container entrypoint.
#
# State lives in $POE_DIR (default /data — mount a volume there).
# Identity files (device.key, peer.key, ticket.seed, xmss.key) sit
# in the directory root; the chain state sits in store/ next to
# finstate.bin. Restarts resume from that state untouched.
#
# Optional environment:
#   POE_BUNDLE_URL  — when set (and different from the last applied
#     URL), the entrypoint downloads this epoch bundle, replaces the
#     local chain state with it (identity files are KEPT, so the
#     node's machine and peer ids survive), and starts with
#     --sync-from. This is the join-the-running-chain lever: a
#     bundle stays usable while the gap to the frontier fits the
#     nodes' served-history retention (~512 epochs ≈ 6.8 hours).
#     Changing the URL re-syncs; removing it resumes normally.
#   POE_PEERS       — comma-separated multiaddrs to dial at start
#     (e.g. "/dns4/host/tcp/12345/p2p/12D3..."). A node behind a
#     public proxy usually needs none: reachable nodes are dialed
#     BY the bootstraps, and gossip flows both ways on that
#     connection.
set -e
DIR="${POE_DIR:-/data}"
mkdir -p "$DIR"

SYNC=""
if [ -n "${POE_BUNDLE_URL:-}" ]; then
    MARKER="$DIR/.bundle_url"
    APPLIED=""
    if [ -f "$MARKER" ]; then
        APPLIED="$(cat "$MARKER")"
    fi
    if [ "$APPLIED" != "$POE_BUNDLE_URL" ] || [ ! -d "$DIR/store" ]; then
        echo "[entrypoint] fetching sync bundle: $POE_BUNDLE_URL"
        curl -fsSL "$POE_BUNDLE_URL" -o /tmp/bundle.bin
        rm -rf "$DIR/store" "$DIR/finstate.bin"
        # Install the fetched bundle as the node's own checkpoint
        # too: if the container recycles mid-boot, the next start
        # finds the marker already applied and plain-starts — and a
        # plain start's fallback syncs from $DIR/bundle.bin. Without
        # this copy, a stale checkpoint from a previous lineage
        # shadows the fetched anchor (seen 2026-11-14: a recycled
        # start silently resumed a fork bundle at epoch 162 instead
        # of the epoch-209 anchor it had just fetched).
        cp /tmp/bundle.bin "$DIR/bundle.bin"
        SYNC="--sync-from /tmp/bundle.bin"
        printf %s "$POE_BUNDLE_URL" > "$MARKER"
    fi
fi

PEERS=""
if [ -n "${POE_PEERS:-}" ]; then
    OLDIFS="$IFS"
    IFS=','
    for p in $POE_PEERS; do
        PEERS="$PEERS --peer $p"
    done
    IFS="$OLDIFS"
fi

# Word splitting of $SYNC/$PEERS is intended (they are flag lists).
exec /usr/local/bin/poe-node testnet \
    --dir "$DIR" \
    --listen /ip4/0.0.0.0/tcp/41001 \
    $SYNC $PEERS
