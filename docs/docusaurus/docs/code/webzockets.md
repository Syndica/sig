# Webzockets

A WebSocket (RFC 6455) library for Zig 0.14.1, built on `libxev`. Server and client. No hidden allocators — all memory is allocated through caller-provided allocators with caller-configured pool sizes and limits. Sends are zero-copy. Server connections are memory-pooled; client connections are caller-owned.

## Quick Start

See [examples/echo_server.zig](examples/echo_server.zig) and [examples/simple_client.zig](examples/simple_client.zig).

## Usage Rules

### Buffer Lifetime

- **Server `sendText`/`sendBinary`**: zero-copy. Keep buffer alive until `onWriteComplete`.
- **Client `sendText`/`sendBinary`**: masks in-place (XOR). Don't read/free/reuse until `onWriteComplete`.
- **Read data in callbacks**: transient — points into internal buffers reused after callback returns. Copy if needed.
- **`sendPing`/`sendPong`**: copies internally. Buffer can be freed immediately. Does not trigger `onWriteComplete`.

### Write Concurrency

- **One data write at a time.** Second `sendText`/`sendBinary` before completion returns `error.WriteBusy`. Queue from `onWriteComplete`.
- **Control frames** (`sendPing`/`sendPong`) use a separate internal queue (256 bytes). `error.QueueFull` on overflow.

### Connection State

- **Sends on non-`.open` connections** return `error.InvalidState`. `close()` no-ops if already closing.
- **`onClose` fires exactly once.** Server connections are pool-released afterward — don't reference them. Client connections require caller `deinit()`.
- **`onWriteComplete` fires even on disconnect** (so callers can free buffers).
- **Idle timeout** (optional, server only) sends `close(.going_away, "")`, following normal close handshake.
- **Close-handshake timeout** force-disconnects if peer doesn't respond.

### Handler Lifecycle (Server)

- **`Handler.init()`** runs before the 101 response. Return error to reject (socket closed, no HTTP response).
- **Handler Context:** handlers declare `pub const Context = T` (or `void`). If non-void, set `Config.handler_context: *T`; it’s passed to `Handler.init` as the second parameter. The pointer must remain valid for any handshake/connection that might call `init` or `onHandshakeFailed`.
- **`onHandshakeFailed`** (optional): called if the handshake fails _after_ `init` succeeds (e.g., connection pool exhausted, write error, server shutdown). Use it to clean up resources allocated in `init`. Neither `onOpen` nor `onClose` will fire.
- **Handler is embedded by value** in the pooled connection — no self-referential fields.

### Platform

- **macOS (kqueue) / Linux (epoll):** `xev.Loop` must be initialized with a `ThreadPool`. libxev dispatches socket close operations to the thread pool on these backends; without one, closes fail and FDs leak. Both `Server.init` and `Client.init` assert that the thread pool is set.

### Timers

- **Idle timeout** (`idle_timeout_ms`, server only, default `null`): sends close on inactivity. Resets on each read.
- **Close-handshake timeout** (`close_timeout_ms`, default 5000ms): force-disconnects if peer doesn't complete close handshake.
- **libxev tip:** prefer `Timer.cancel()` over raw `.cancel` completions (different behavior across backends). Note: cancellation still delivers the original callback with `error.Canceled`.

### Event Loop

Single-threaded. All callbacks run on the `loop.run()` thread. No locking needed; handlers must not block.

### Client PRNG

- Client handshake key generation and RFC 6455 masking require a caller-provided `ClientMaskPRNG` (a thin wrapper around `std.Random.DefaultCsprng`).
- `ClientMaskPRNG` is **not thread-safe**; only use it from the `loop.run()` thread and do not share it across loops/threads.
- The pointer must remain valid and **must not move** for the lifetime of any `ClientConnection` using it.

### UTF-8 Validation

The library delivers text messages to `onMessage` without validating UTF-8. Per RFC 6455 §8.1, endpoints must close the connection on invalid UTF-8 in text frames. Validate in your handler:

See [autobahn/server/server.zig](autobahn/server/server.zig) for a complete example (required to pass Autobahn section 6.x tests).

## Architecture

```
                          ┌──────────────────────┐
                          │   User Application   │
                          │  (defines Handler)   │
                          └──┬───────┬────────┬──┘
                             │       │        │
           ┌─────────────────┘       │        └─────────────────┐
           ▼                         │                          ▼
┌─────────────────────┐              │               ┌─────────────────────┐
│       Server        │              │               │   Client (transient)│
│  TCP accept loop +  │              │               │  TCP connect +      │
│    memory pools     │              │               │  handshake, then    │
└──────────┬──────────┘              │               │  can be discarded   │
           │                         │               └──────────┬──────────┘
    ┌──────┴──────┐                  │                          ▼
    ▼             ▼                  │               ┌─────────────────────┐
 ┌────────┐  ┌────────┐              │               │  ClientConnection   │
 │  Hand- │  │  Hand- │              │               │  (caller-provided)  │
 │  shake │  │  shake │              │               └──────────┬──────────┘
 │ pooled │  │ pooled │              │                          │
 └───┬────┘  └───┬────┘              │                          │
     ▼           ▼                   │                          │
 ┌────────┐  ┌────────┐              │                          │
 │  Conn  │  │  Conn  │              │                          │
 │ pooled │  │ pooled │              │                          │
 └───┬────┘  └───┬────┘              │                          │
     └─────┬─────┘                   │                          │
           └─────────────────────────┼──────────────────────────┘
                                     ▼
                   ┌────────────────────────────────────┐
                   │         libxev Event Loop          │
                   └────────────────────────────────────┘
```

**Server-side:** Each `Handshake` and `Connection` is a self-contained pooled type with its own read buffer and back-pointer to the server.

**Client-side:** The client is transient — connects TCP, handshakes, initializes a caller-provided `*ClientConnection`, then can be discarded.

### Connection Lifecycle

**Server:**
`TCP accept → Handshake (pool) → read HTTP upgrade → validate → Handler.init() → 101 response → Connection (pool) → onOpen → read loop (parse/unmask/reassemble/dispatch) → close handshake → onClose → release to pool`

**Client:**
`Client.connect() → write HTTP upgrade → read 101 → validate Sec-WebSocket-Accept → init ClientConnection (zero-copy handoff of leftover bytes) → onOpen → read loop (parse/reassemble/dispatch) → close handshake → onClose → deinit`

## File Structure

```
src/
├── root.zig              Public API re-exports
├── types.zig             Protocol types, enums, error sets
├── mask.zig              XOR masking (SIMD-accelerated)
├── frame.zig             Frame parsing/encoding (RFC 6455 §5)
├── http.zig              HTTP parsing/encoding
├── reader.zig            Frame reader with buffer management
├── buffer.zig            Buffer pool for large messages
├── control_queue.zig     Ring buffer for outbound control frames
├── server/
│   ├── server.zig        TCP listener, accept loop, graceful shutdown
│   ├── slot_pool.zig     Memory pool with active count tracking
│   ├── handshake.zig     HTTP upgrade handshake (poolable)
│   └── connection.zig    WebSocket state machine (poolable)
└── client/
    ├── client.zig        Transient: connect, handshake, init connection
    ├── handshake.zig     Client-side HTTP upgrade state machine
    └── connection.zig    WebSocket state machine (caller-owned)

examples/                 Echo server and client examples
e2e_tests/                Client-server integration tests
  server/                 Server behavior tests
  client/                 Client behavior tests
  support/                Shared test helpers, raw client
autobahn/                 Autobahn conformance suite runners
```

### Module Dependencies

```
root.zig
├── types.zig
├── mask.zig
├── buffer.zig
├── control_queue.zig      ← types
├── frame.zig              ← types, mask
├── http.zig               ← types
├── reader.zig             ← types, frame, buffer
├── server/
│   ├── server.zig         ← slot_pool, server/handshake, server/connection, xev
│   ├── slot_pool.zig      ← std.heap.MemoryPool
│   ├── handshake.zig      ← http, types, server/connection, xev
│   └── connection.zig     ← types, frame, reader, buffer, control_queue, xev
└── client/
    ├── client.zig         ← client/handshake, client/connection, buffer, xev
    ├── handshake.zig      ← http, xev
    └── connection.zig     ← types, frame, reader, buffer, mask, control_queue, xev
```

## API Reference

### Server Config

```zig
const EchoServer = ws.Server(EchoHandler, 4096, 64 * 1024);
//                           Handler     ^read  ^pool buffer
//                                       buf sz  size

const Config = struct {
    address: std.net.Address,
    tcp_accept_backlog: u31 = 128,
    max_message_size: usize = 16 * 1024 * 1024,
    initial_handshake_pool_size: usize = 16,
    initial_connection_pool_size: usize = 64,
    max_handshakes: ?usize = null,
    max_connections: ?usize = null,
    buffer_pool_preheat: usize = 8,
    idle_timeout_ms: ?u32 = null,
    close_timeout_ms: u32 = 5_000,
    handler_context: …,  // if Handler.Context != void: *Handler.Context, else: void ({})
};
```

### Client Config

```zig
const SimpleClient = ws.Client(ClientHandler, 4096);
//                              Handler       ^read buf sz

const Config = struct {
    address: std.net.Address,
    path: []const u8 = "/",
    max_message_size: usize = 16 * 1024 * 1024,
    close_timeout_ms: u32 = 5_000,
};
```

The client is a transient value type. `init` doesn't allocate. Caller provides a `*ClientConnection`, allocator, `*BufferPool`, and `*ClientMaskPRNG`:

```zig
var seed: [ws.ClientMaskPRNG.secret_seed_length]u8 = undefined;
std.crypto.random.bytes(&seed);
var csprng = ws.ClientMaskPRNG.init(seed);

var conn: SimpleClient.Conn = undefined;
var client = SimpleClient.init(allocator, &loop, &handler, &conn, &buf_pool, &csprng, .{
    .address = std.net.Address.parseIp4("127.0.0.1", 8080) catch unreachable,
    .path = "/",
    .max_message_size = 16 * 1024 * 1024,
    .close_timeout_ms = 5_000,
});
try client.connect();
// After handshake, `conn` is live — client can be discarded
```

### Handler Interface

```zig
// Required
fn onMessage(self: *Handler, conn: *Conn, message: Message) void
fn onWriteComplete(self: *Handler, conn: *Conn) void
fn onClose(self: *Handler, conn: *Conn) void

// Optional
fn onOpen(self: *Handler, conn: *Conn) void
fn onPing(self: *Handler, conn: *Conn, data: []const u8) void
fn onPong(self: *Handler, conn: *Conn, data: []const u8) void

// Optional (client-only)
fn onSocketClose(self: *Handler) void

// Optional (server-only)
fn onHandshakeFailed(self: *Handler) void

// Server-only (required)
pub const Context = void; // or a real type T
fn init(request: http.Request, context: if (Context == void) void else *Context) !Handler
```

If `onPing` is not declared, auto-pong replies with latest-wins semantics. If declared, auto-pong is disabled — handler must call `conn.sendPong()`.

Server `init` runs before 101. Return error to reject. `onHandshakeFailed` fires if the handshake fails after `init` succeeds (pool exhaustion, write error, shutdown); use it to clean up `init`-allocated resources.

### Connection Methods

```zig
fn sendText(data) !void    // server: []const u8 (zero-copy), client: []u8 (zero-copy, masked in-place)
fn sendBinary(data) !void  // same as above
fn sendPing(data) !void    // copies internally, max 125 bytes
fn sendPong(data) !void    // copies internally, max 125 bytes
fn close(code: CloseCode, reason: []const u8) void
```

## Tests

Unit tests colocated in source files. E2E tests in `e2e_tests/`.

```bash
zig build test --summary all
```

## Autobahn Testsuite

Industry-standard WebSocket conformance suite. **Requires Docker.**

```bash
bash autobahn/server/run.sh   # Results: autobahn/server/reports/index.html
bash autobahn/client/run.sh   # Results: autobahn/client/reports/index.html
```

**Excluded:** 12.x / 13.x (permessage-deflate not implemented)

## Current Limitations

- **No custom response headers in the upgrade response (server):** The 101 response is fixed — no way to add `Sec-WebSocket-Protocol` or other headers.
- **No permessage-deflate (compression):** RFC 7692 is not implemented. Adds complexity around buffer ownership for the send API since compressed frames can't be zero-copy in the same way.
- **No DNS resolution (client):** `Config.address` takes a `std.net.Address` (IP only). The `Host` header is formatted from this address, but real-world servers typically expect the domain name.
- **No TLS:** Most important for the client — servers can sit behind a TLS terminator.
