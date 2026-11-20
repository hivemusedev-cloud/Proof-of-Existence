#!/bin/sh
# Standalone node start rule — mirrors the host testnet's
# run-node.sh: a data dir with no store yet starts from the
# bundle firstboot staged into it; a dir with a store starts
# plain (finstate resume; the node itself falls back to the
# bundle if the finstate is unreadable). Without this, a fresh
# standalone refuses to start at all: the chain has started
# and a plain start on an empty dir is refused by design
# (defect D7, found 2026-11-20 from the persisted node log).
DIR=/data/poe-node
if [ ! -d "$DIR/store" ] && [ -f "$DIR/bundle.bin" ]; then
    exec /usr/lib/poe/poe-node testnet --dir "$DIR" --sync-from "$DIR/bundle.bin"
fi
exec /usr/lib/poe/poe-node testnet --dir "$DIR"
