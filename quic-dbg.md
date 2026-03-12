# QUIC/lsquic ACK Frame Crash — Debugging Notes

## The Bug

When running the sig validator with `runMockTransfers`, an **illegal instruction** crash occurs in lsquic's `ietf_v1_gen_ack_frame`. The same QUIC client code works fine when run standalone via `test_send_transactions.zig`.

### Crash trace

```
Illegal instruction at address 0x29a92c6
lsquic/src/liblsquic/lsquic_parse_ietf_v1.c:1125:1: in ietf_v1_gen_ack_frame
lsquic/src/liblsquic/lsquic_full_conn_ietf.c:1902:9: in generate_ack_frame_for_pns
lsquic/src/liblsquic/lsquic_full_conn_ietf.c:1996:17: in generate_ack_frame
lsquic/src/liblsquic/lsquic_full_conn_ietf.c:8550:13: in ietf_full_conn_ci_tick
lsquic/src/liblsquic/lsquic_engine.c:3107:19: in lsquic_engine_process_conns
src/net/quic_client.zig:200:47: in callback (sig)
```

The crash is at the **closing brace** of `ietf_v1_gen_ack_frame` (line 1125). This is characteristic of a **UBSan trap** — Zig compiles C code with `-Doptimize=ReleaseSafe` which enables undefined behavior sanitizers that emit `ud2` (illegal instruction) when UB is detected.

## Call chain

```
quic_client.zig onTick
  → lsquic_engine_process_conns
    → ietf_full_conn_ci_tick
      → generate_ack_frame
        → generate_ack_frame_for_pns
          → pf_gen_ack_frame (= ietf_v1_gen_ack_frame)
```

## Architecture

- **One QUIC engine** exists (for transaction sending). The shred network is pure UDP.
- The QUIC client runs in a single xev/io_uring event loop thread (no threading issue).
- `onTick` (every 100ms) and `onPacketsIn` (on UDP receive) both run on the same thread.
- The QUIC client binds to `0.0.0.0:4444` (hardcoded).

## Why it works standalone but not in the validator

Both paths use the same `quic_client.zig` code. The key difference:

| | test_send_transactions | validator + runMockTransfers |
|---|---|---|
| Startup | Immediate | After snapshot download + replay (~10 min) |
| Concurrency | Single-purpose process | Many services (gossip, shred, replay, RPC) |
| Transaction timing | Sequential: send, wait for confirm, send next | Continuous: tick every 100ms |
| Connection lifetime | Short-lived | Long-lived (connections persist across many ticks) |

By the time the validator sends its first transaction, QUIC connections may have been alive much longer with varying packet exchange patterns, potentially causing the `rechist` (receive history) to accumulate ranges that trigger arithmetic issues.

## Suspected UB locations in `ietf_v1_gen_ack_frame`

All variables are `uint64_t` (unsigned), so wrapping is defined in C. However, specific UBSan checks (e.g., pointer arithmetic, shift overflow) may still trigger.

1. **`time_diff = now - rechist_largest_recv(rechist)`** — underflows if `now < largest_recv` (stale timestamp)
2. **`gap = prev_low - range->high - 1`** — underflows if `prev_low <= range->high` (misordered rechist ranges)
3. **`vint_val2bits(gap - 1)`** — underflows if `gap == 0`
4. **`assert(ecn_needs <= AVAIL())`** — was already fixed on this branch (replaced with safe downgrade)

## Debug prints added

### lsquic C layer — `lsquic_parse_ietf_v1.c`

- Logs first range `[high - low]` and `outbuf_sz` on entry
- Logs `now` vs `largest_recv` and warns if `now < largest_recv`
- Logs `maxno`, `range->low`, `packno_diff`, `time_diff`
- For each subsequent range: logs `prev_low`, `range->high/low`, `gap`, `rsize`
- Explicit **ERROR** messages if any subtraction would underflow

### lsquic C layer — `lsquic_full_conn_ietf.c`

- Logs PNS, available buffer size, and timestamp before `pf_gen_ack_frame`
- Logs return value after the call

### Zig layer — `quic_client.zig`

- `onTick`: logs connection count and packets queued per tick
- `onPacketsIn`: logs byte count and source address of every incoming UDP packet
- Changed `@panic` on `lsquic_engine_packet_in` failure to a warn log (prevents crash on single malformed packet)

## How to reproduce and capture

```bash
# Build with ReleaseSafe (enables UBSan for C code)
zig build -Doptimize=ReleaseSafe

# Run validator, capturing stderr (where ACKDBG prints go)
./zig-out/bin/sig validator \
  --rpc-port 8899 \
  --cluster testnet \
  --skip-snapshot-validation \
  2>&1 | tee debug_run.log

# After crash, inspect:
grep "ACKDBG\|ERROR\|(QUIC)" debug_run.log
```

The `ACKDBG gen_ack: ERROR` lines will pinpoint the exact arithmetic underflow that triggered UBSan.

## Existing lsquic fixes on `harnew/fix-ub` branch

1. **NULL deref UB**: Replaced `(uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, ...)` with `offsetof(lsquic_stream_t, ...)` in `lsquic_full_conn.c` and `lsquic_full_conn_ietf.c`
2. **ECN assert crash**: Replaced `assert(ecn_needs <= AVAIL())` with safe downgrade to non-ECN ACK frame in `lsquic_parse_ietf_v1.c`
