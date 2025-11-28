#!/usr/bin/env bash
set -euo pipefail

SIG_CONFIG="${SIG_CONFIG:-~/.local/share/sig/}"

solana-keygen new --no-bip39-passphrase -o "${SIG_CONFIG}/identity.json"
solana-keygen new --no-bip39-passphrase -o "${SIG_CONFIG}/withdrawer.json"
solana-keygen new --no-bip39-passphrase -o "${SIG_CONFIG}/vote-account.json"

read -rp $'\n\nFund '"$(solana -k "${SIG_CONFIG}/identity.json" address)"$' with some SOL from https://faucet.solana.com/, then press enter.'

solana -k "${SIG_CONFIG}/identity.json" -ut create-vote-account \
    "${SIG_CONFIG}/vote-account.json" \
    "${SIG_CONFIG}/identity.json" \
    "${SIG_CONFIG}/withdrawer.json"
