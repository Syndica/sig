# Solana's Gossip Specification

This post will describe how Solana's gossip protocol works in-depth, as well as implementation details of Sig's gossip.

For an introduction to Solana's gossip protocol, check out the technical sections of our [Sig announcement blog post](https://blog.syndica.io/introducing-sig-by-syndica-an-rps-focused-solana-validator-client-written-in-zig/).

Checkout the full associated blog post here: [https://blog.syndica.io/sig-engineering-1-gossip-protocol/](https://blog.syndica.io/sig-engineering-1-gossip-protocol/).

## Repository File Outline 

- `service.zig`: main logic for reading, processing, and sending gossip messages
- `table.zig`: where gossip data is stored 
- `data.zig`: various gossip data structure definitions 
- `pull_request.zig`: logic for sending pull *requests* 
- `pull_response.zig`: logic for sending pull *responses* (/handling incoming pull requests)
- `gossip_shards.zig`: datastructure which stores gossip data hashes for quick lookup - used in `gossip_table` and constructing pull responses
- `active_set.zig`: logic for deriving a list of peers to send push messages to
- `ping_pong.zig`: logic for sending ping/pong messages as a heartbeat check

A gossip spy is, in essence, software written to do two things: store data and send/receive requests.

## Benchmarks 

benchmarks are located at the bottom of `service.zig`.

to run the benchmarks: 
- build sig in `ReleaseSafe` (ie, `zig build -Doptimize=ReleaseSafe`)
- run `./zig-out/bin/benchmark gossip`

this includes processing times for pings, push messages, pull responses, and 
pull requests.

## Fuzzing

the fuzzing client is located in `fuzz.zig`. 

to run the client
- start a sig gossip in a terminal (ie, listening on `8001`)
- build the fuzz client in `ReleaseSafe` (ie, `zig build -Doptimize=ReleaseSafe`)
- run the fuzz client pointing to sig with some seed and some number of random messages 
to send: `./zig-out/bin/fuzz <entrypoint> <seed> <num_messages>` (eg, `./zig-out/bin/fuzz 127.0.0.1:8001 19 100000`)