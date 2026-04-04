# Generated Docs

1. Run `zig build docs`

2. Serve it with a HTTP server, e.g. `python -m http.server -b 127.0.0.1 8000 -d zig-out/docs`

# Running Shred Receive

1. Use Agave to create a leader schedule text file, e.g.

`solana leader-schedule > schedule.txt`

2. Start up v2

`zig build run -- config/testnet.zig.zon`

# Running with tracy

1. Build with `-Denable-tracy`

2. Use `.sandboxing_mode = .threaded` in your config