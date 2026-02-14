const std = @import("std");
const Allocator = std.mem.Allocator;
const frame = @import("frame.zig");
const types = @import("types.zig");

/// WebSocket frame reader with automatic buffer tier escalation.
///
/// Manages read buffer state with automatic tier escalation:
/// - Starts with an embedded buffer for small messages
/// - Upgrades to dynamic buffer when needed
/// - Retains larger buffer for subsequent messages (performance optimization)
/// - Restores to embedded only on explicit reset()
///
/// Buffer layout:
///
/// ```
///     buf
///     ├──────────────────────────────────────────────────────┤
///     │  consumed   │   unprocessed data   │   free space    │
///     │  (already   │   (pending parse/    │   (available    │
///     │  parsed)    │    delivery)         │    for reads)   │
///     ├─────────────┼──────────────────────┼─────────────────┤
///     0           start                   pos            buf.len
///                   │                      │                 │
///                   ├── data() ────────────┤                 │
///                   │  (start..pos)        │                 │
///                                          ├─ readSlice() ───┤
///                                          │  (pos..buf.len) │
/// ```
///
/// - `buf[0..start]` — already consumed frames, reclaimable by `compact()`
/// - `buf[start..pos]` — received data not yet fully parsed/delivered (`data()`)
/// - `buf[pos..buf.len]` — writable region for the next TCP read (`readSlice()`)
/// - `compact()` shifts unprocessed data to the front: start→0, pos→dataLen
/// - `consume(n)` advances start by n after a frame is processed
///
/// Parameterized by `Role` to select the correct frame validation:
/// - `.server`: validates that frames are masked (client-to-server)
/// - `.client`: validates that frames are unmasked (server-to-client)
pub fn Reader(comptime role: types.Role) type {
    return struct {
        /// Current buffer for reading frames, starts as embedded and may upgrade to dynamic.
        buf: []u8,
        /// Saved reference to embedded buffer.
        embedded_buf: []u8,
        /// Allocator for dynamic buffer allocation.
        allocator: Allocator,
        /// Position within buf that we've read into (end of data).
        pos: usize,
        /// Position in buf where the current message starts.
        start: usize,
        max_message_size: usize,
        /// Opcode of the first fragment in an in-progress fragmented message (null if none).
        fragment_opcode: ?types.Opcode,
        /// Accumulator for fragmented message payloads.
        fragment_buf: std.ArrayListUnmanaged(u8),

        const ReaderSelf = @This();

        /// Initialize reader with embedded buffer.
        pub fn init(
            embedded_buf: []u8,
            allocator: Allocator,
            max_message_size: usize,
        ) ReaderSelf {
            return .{
                .buf = embedded_buf,
                .embedded_buf = embedded_buf,
                .allocator = allocator,
                .pos = 0,
                .start = 0,
                .max_message_size = max_message_size,
                .fragment_opcode = null,
                .fragment_buf = .{},
            };
        }

        /// Clean up any non-embedded buffer and fragment state.
        pub fn deinit(self: *ReaderSelf) void {
            self.cleanupFragments();
            self.releaseCurrentBuffer();
        }

        /// Reset state for connection reuse.
        pub fn reset(self: *ReaderSelf) void {
            self.cleanupFragments();
            self.releaseCurrentBuffer();
            self.buf = self.embedded_buf;
            self.pos = 0;
            self.start = 0;
        }

        fn cleanupFragments(self: *ReaderSelf) void {
            if (self.fragment_buf.capacity > 0) {
                self.fragment_buf.deinit(self.allocator);
                self.fragment_buf = .{};
            }
            self.fragment_opcode = null;
        }

        /// Writable slice for xev TCP read, returns a slice with len > 0.
        pub fn readSlice(self: *ReaderSelf) error{OutOfMemory}![]u8 {
            const tail_free = self.availableSpace();

            if (self.start > 0) {
                // Hybrid reclaim heuristic: compact early when tail free space is
                // small (to avoid a tiny read), but only if shifting is
                // amortized-cheap (`start >= live_len`).
                const compact_threshold = @max(1, self.buf.len / 16);
                if (tail_free > 0 and
                    tail_free <= compact_threshold and
                    self.start >= self.dataLen())
                {
                    self.compact();
                } else if (tail_free == 0) {
                    // Buffer full but has consumed bytes at front — reclaim them.
                    self.compact();
                }
            }

            // Ensure a writable tail exists (len > 0).
            // This is an unusual case because nextMessage will be consuming data and advancing
            // start/pos and calling requireCapacity as needed. But if the caller just calls
            // readSlice repeatedly without calling nextMessage then we must grow the buffer
            // to avoid returning an empty slice.
            if (self.availableSpace() == 0) {
                self.requireCapacity(self.buf.len * 2) catch return error.OutOfMemory;
            }
            return self.buf[self.pos..];
        }

        /// Advance pos after successful read.
        pub fn advancePos(self: *ReaderSelf, n: usize) void {
            self.pos += n;
        }

        /// Returns next complete message, or null if more data needed.
        /// Call in a loop until null. Control frames are returned immediately
        /// even mid-fragment-sequence. Fragments are assembled internally.
        ///
        /// NOTE: we just re-parse and validate the header each time this is called
        /// rather than build a state machine since it is very cheap to do and
        /// keeps things simple. For messages large enough to not fit in a single
        /// TCP read the repeated work is inconsequential.
        pub fn nextMessage(
            self: *ReaderSelf,
        ) error{ ProtocolError, MessageTooBig, OutOfMemory }!?types.Message {
            while (true) {
                const current_data = self.data();
                if (current_data.len == 0) return null;

                const header = frame.parseHeader(current_data) catch |err| {
                    return switch (err) {
                        error.InsufficientData => null,
                        else => error.ProtocolError,
                    };
                };

                // Validate per RFC 6455
                header.validate() catch return error.ProtocolError;
                switch (role) {
                    .server => header.validateServerBound() catch return error.ProtocolError,
                    .client => header.validateClientBound() catch return error.ProtocolError,
                }

                if (header.payload_len > self.max_message_size) {
                    return error.MessageTooBig;
                }

                const total_frame_size = header.totalLen();

                // Have we received the full frame yet?
                if (current_data.len < total_frame_size) {
                    // Ensure the buffer can fit the full frame for when the rest arrives.
                    self.requireCapacity(@intCast(total_frame_size)) catch return error.OutOfMemory;
                    return null; // Need more data from the wire
                }

                const payload_len: usize = @intCast(header.payload_len);
                const payload = current_data[header.header_len..][0..payload_len];
                header.unmaskPayload(payload);

                // Consume the frame bytes
                self.consume(@intCast(total_frame_size));

                // Dispatch by opcode
                switch (header.opcode) {
                    .text, .binary => {
                        if (header.fin) {
                            // Complete single-frame message
                            if (self.fragment_opcode != null) {
                                return error.ProtocolError; // nested fragment
                            }
                            const msg_type: types.Message.Type =
                                if (header.opcode == .text) .text else .binary;

                            return .{ .type = msg_type, .data = payload };
                        } else {
                            // First frame of a fragmented message
                            if (self.fragment_opcode != null) {
                                return error.ProtocolError; // nested fragment
                            }
                            self.fragment_opcode = header.opcode;
                            self.fragment_buf.clearRetainingCapacity();
                            self.fragment_buf.appendSlice(
                                self.allocator,
                                payload,
                            ) catch return error.OutOfMemory;
                            continue;
                        }
                    },
                    .continuation => {
                        const frag_op = self.fragment_opcode orelse {
                            return error.ProtocolError; // unexpected continuation
                        };
                        const new_len = self.fragment_buf.items.len + payload.len;
                        if (new_len > self.max_message_size) {
                            return error.MessageTooBig;
                        }
                        self.fragment_buf.appendSlice(
                            self.allocator,
                            payload,
                        ) catch return error.OutOfMemory;

                        if (header.fin) {
                            // Fragmented message complete
                            const msg_type: types.Message.Type =
                                if (frag_op == .text) .text else .binary;

                            const result: types.Message = .{
                                .type = msg_type,
                                .data = self.fragment_buf.items,
                            };
                            // Clear fragment state — data remains valid until next nextMessage()/read cycle
                            self.fragment_opcode = null;
                            return result;
                        }
                        continue;
                    },
                    .ping => return .{ .type = .ping, .data = payload },
                    .pong => return .{ .type = .pong, .data = payload },
                    .close => return .{ .type = .close, .data = payload },
                }
            }
        }

        /// Get the current unprocessed data (from start to pos).
        fn data(self: *const ReaderSelf) []u8 {
            return self.buf[self.start..self.pos];
        }

        /// Get length of current unprocessed data.
        fn dataLen(self: *const ReaderSelf) usize {
            return self.pos - self.start;
        }

        /// Number of writable bytes at the tail of the buffer.
        pub fn availableSpace(self: *const ReaderSelf) usize {
            return self.buf.len - self.pos;
        }

        /// Reclaim consumed bytes at the front of the buffer by compacting,
        /// but only when the buffer is completely full. Does not allocate.
        pub fn compactIfFull(self: *ReaderSelf) void {
            if (self.pos >= self.buf.len and self.start > 0) {
                self.compact();
            }
        }

        /// Ensure buffer has total capacity for at least `required` bytes.
        /// Compacts if that alone satisfies the requirement, otherwise upgrades
        /// to dynamic buffer.
        fn requireCapacity(self: *ReaderSelf, required: usize) !void {
            // If current capacity is sufficient, compact to make free space
            // contiguous at the end. No heuristic here since we've already
            // determined the capacity required.
            if (required <= self.buf.len) {
                self.compact();
                return;
            }

            // Compaction won't be enough — need to upgrade buffer
            const current_data_len = self.dataLen();

            // Dynamic allocation - round up to next power of 2
            // to avoid repeated reallocations for incrementally growing messages
            const alloc_size = std.math.ceilPowerOfTwo(usize, required) catch required;
            const new_buf = try self.allocator.alloc(u8, alloc_size);
            if (current_data_len > 0) {
                @memcpy(new_buf[0..current_data_len], self.data());
            }
            self.releaseCurrentBuffer();
            self.buf = new_buf;
            self.pos = current_data_len;
            self.start = 0;
        }

        /// Shift unprocessed data to the front of the buffer, reclaiming consumed space.
        fn compact(self: *ReaderSelf) void {
            if (self.start == 0) return;
            const current_data_len = self.dataLen();
            if (current_data_len > 0) {
                std.mem.copyForwards(u8, self.buf[0..current_data_len], self.data());
            }
            self.pos = current_data_len;
            self.start = 0;
        }

        /// After processing a message, advance the start position.
        fn consume(self: *ReaderSelf, bytes: usize) void {
            self.start += bytes;

            // If we've consumed all data, reset positions but keep buffer
            if (self.start == self.pos) {
                self.pos = 0;
                self.start = 0;
            }
        }

        /// Free the current buffer if it's not embedded.
        fn releaseCurrentBuffer(self: *ReaderSelf) void {
            if (self.buf.ptr != self.embedded_buf.ptr) {
                self.allocator.free(self.buf);
            }
        }
    };
}

const testing = std.testing;

const ServerReader = Reader(.server);

test "Reader: init with embedded buffer" {
    var embedded_buf: [64]u8 = undefined;
    var reader = ServerReader.init(&embedded_buf, testing.allocator, 1024);
    defer reader.deinit();

    try testing.expectEqual(reader.embedded_buf.ptr, reader.buf.ptr);
    try testing.expectEqual(@as(usize, 0), reader.pos);
    try testing.expectEqual(@as(usize, 64), (try reader.readSlice()).len);
}

test "Reader: availableSpace after init" {
    var embedded_buf: [64]u8 = undefined;
    var reader = ServerReader.init(&embedded_buf, testing.allocator, 1024);
    defer reader.deinit();

    try testing.expectEqual(@as(usize, embedded_buf.len), reader.availableSpace());
}

test "Reader: availableSpace after advancePos" {
    var embedded_buf: [64]u8 = undefined;
    var reader = ServerReader.init(&embedded_buf, testing.allocator, 1024);
    defer reader.deinit();

    reader.advancePos(10);
    try testing.expectEqual(@as(usize, embedded_buf.len - 10), reader.availableSpace());
}

test "Reader: availableSpace when full" {
    var embedded_buf: [64]u8 = undefined;
    var reader = ServerReader.init(&embedded_buf, testing.allocator, 1024);
    defer reader.deinit();

    reader.pos = embedded_buf.len;
    try testing.expectEqual(@as(usize, 0), reader.availableSpace());
}

test "Reader: compactIfFull reclaims consumed bytes" {
    var embedded_buf: [16]u8 = undefined;
    var reader = ServerReader.init(&embedded_buf, testing.allocator, 1024);
    defer reader.deinit();

    // Simulate full buffer with 6 bytes already consumed.
    reader.start = 6;
    reader.pos = embedded_buf.len;

    reader.compactIfFull();
    try testing.expectEqual(@as(usize, 6), reader.availableSpace());
    try testing.expectEqual(@as(usize, 0), reader.start);
    try testing.expectEqual(@as(usize, 10), reader.pos);
}

test "Reader: compactIfFull does nothing when not full" {
    var embedded_buf: [16]u8 = undefined;
    var reader = ServerReader.init(&embedded_buf, testing.allocator, 1024);
    defer reader.deinit();

    // Buffer has consumed bytes but is not full — should not compact.
    reader.start = 4;
    reader.pos = 10;

    reader.compactIfFull();
    try testing.expectEqual(@as(usize, 4), reader.start);
    try testing.expectEqual(@as(usize, 10), reader.pos);
}

test "Reader: requireCapacity upgrades to dynamic" {
    var embedded_buf: [64]u8 = undefined;
    @memcpy(embedded_buf[0..5], "hello");

    var reader = ServerReader.init(&embedded_buf, testing.allocator, 1024);
    defer reader.deinit();
    reader.pos = 5;

    // Require more than embedded size — escalates to dynamic
    try reader.requireCapacity(128);

    try testing.expect(reader.buf.ptr != reader.embedded_buf.ptr);
    try testing.expectEqual(@as(usize, 128), reader.buf.len);
    try testing.expectEqual(@as(usize, 5), reader.pos);
    try testing.expectEqual(@as(usize, 0), reader.start);
    try testing.expectEqualStrings("hello", reader.data());
}

test "Reader: consume keeps larger buffer" {
    var embedded_buf: [64]u8 = undefined;
    var reader = ServerReader.init(&embedded_buf, testing.allocator, 1024);
    defer reader.deinit();

    // Upgrade to dynamic
    try reader.requireCapacity(128);
    try testing.expect(reader.buf.ptr != reader.embedded_buf.ptr);

    // Simulate reading 100 bytes
    reader.pos = 100;

    // Consume all data
    reader.consume(100);

    // Should stay at dynamic (not restore to embedded)
    try testing.expect(reader.buf.ptr != reader.embedded_buf.ptr);
    try testing.expectEqual(@as(usize, 0), reader.pos);
    try testing.expectEqual(@as(usize, 0), reader.start);
}

test "Reader: requireCapacity uses power-of-2 rounding" {
    var embedded_buf: [64]u8 = undefined;
    var reader = ServerReader.init(&embedded_buf, testing.allocator, 1024);
    defer reader.deinit();

    // Require non-power-of-2 size — should round up
    try reader.requireCapacity(300);

    try testing.expect(reader.buf.ptr != reader.embedded_buf.ptr);
    try testing.expectEqual(@as(usize, 512), reader.buf.len);
}

// --- Test helpers for nextMessage ---

const mask_mod = @import("mask.zig");

/// Write the frame header into `out`, returning the header length written.
fn writeFrameHeader(
    out: []u8,
    opcode: types.Opcode,
    fin: bool,
    payload_len: usize,
    masked: bool,
) usize {
    var byte0: u8 = @intFromEnum(opcode);
    if (fin) byte0 |= 0x80;
    out[0] = byte0;

    const mask_bit: u8 = if (masked) 0x80 else 0;
    var header_len: usize = 2;
    if (payload_len <= 125) {
        out[1] = mask_bit | @as(u8, @truncate(payload_len));
    } else if (payload_len <= 65535) {
        out[1] = mask_bit | 126;
        std.mem.writeInt(u16, out[2..4], @truncate(payload_len), .big);
        header_len = 4;
    } else {
        out[1] = mask_bit | 127;
        std.mem.writeInt(u64, out[2..10], payload_len, .big);
        header_len = 10;
    }
    return header_len;
}

/// Build a masked WebSocket frame into `out`. Returns the slice of `out` that was written.
fn buildMaskedFrame(
    out: []u8,
    opcode: types.Opcode,
    fin: bool,
    payload: []const u8,
    mask_key: [4]u8,
) []u8 {
    var header_len = writeFrameHeader(
        out,
        opcode,
        fin,
        payload.len,
        true,
    );

    @memcpy(out[header_len..][0..4], &mask_key);
    header_len += 4;

    @memcpy(out[header_len..][0..payload.len], payload);
    mask_mod.mask(mask_key, out[header_len..][0..payload.len]);

    return out[0 .. header_len + payload.len];
}

/// Create a server reader with data pre-loaded.
fn testReader(embedded_buf: []u8, max_msg: usize) ServerReader {
    return ServerReader.init(embedded_buf, testing.allocator, max_msg);
}

// --- nextMessage tests ---

test "Reader.nextMessage: single text frame" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    // Build a masked text frame with "Hello"
    var frame_buf: [64]u8 = undefined;
    const f = buildMaskedFrame(&frame_buf, .text, true, "Hello", .{ 0x37, 0xFA, 0x21, 0x3D });
    @memcpy(embedded_buf[0..f.len], f);
    reader.pos = f.len;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.text, msg.type);
    try testing.expectEqualStrings("Hello", msg.data);

    // No more messages
    try testing.expect((try reader.nextMessage()) == null);
}

test "Reader.nextMessage: single binary frame" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var frame_buf: [64]u8 = undefined;
    const f = buildMaskedFrame(&frame_buf, .binary, true, &payload, .{ 0x11, 0x22, 0x33, 0x44 });
    @memcpy(embedded_buf[0..f.len], f);
    reader.pos = f.len;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.binary, msg.type);
    try testing.expectEqualSlices(u8, &payload, msg.data);
}

test "Reader.nextMessage: partial frame returns null" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    // Build a frame but only give partial data
    var frame_buf: [64]u8 = undefined;
    const f = buildMaskedFrame(&frame_buf, .text, true, "Hello", .{ 0x37, 0xFA, 0x21, 0x3D });
    // Only copy part of the frame (header but not full payload)
    const partial_len = 4; // just the header bytes
    @memcpy(embedded_buf[0..partial_len], f[0..partial_len]);
    reader.pos = partial_len;

    try testing.expect((try reader.nextMessage()) == null);
}

test "Reader.nextMessage: control frame (ping)" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    var frame_buf: [64]u8 = undefined;
    const f = buildMaskedFrame(&frame_buf, .ping, true, "ping", .{ 0xAA, 0xBB, 0xCC, 0xDD });
    @memcpy(embedded_buf[0..f.len], f);
    reader.pos = f.len;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.ping, msg.type);
    try testing.expectEqualStrings("ping", msg.data);
}

test "Reader.nextMessage: control frame (close)" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    // Close with status code 1000
    const close_payload = [_]u8{ 0x03, 0xE8 };
    var frame_buf: [64]u8 = undefined;
    const f = buildMaskedFrame(
        &frame_buf,
        .close,
        true,
        &close_payload,
        .{ 0x11, 0x22, 0x33, 0x44 },
    );
    @memcpy(embedded_buf[0..f.len], f);
    reader.pos = f.len;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.close, msg.type);
    try testing.expectEqualSlices(u8, &close_payload, msg.data);
}

test "Reader.nextMessage: fragment reassembly (text)" {
    var embedded_buf: [256]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // Fragment 1: text FIN=0 "Hel"
    const f1 = buildMaskedFrame(&frame_buf, .text, false, "Hel", mask_key);
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    // Fragment 2: continuation FIN=1 "lo"
    const f2 = buildMaskedFrame(&frame_buf, .continuation, true, "lo", mask_key);
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    reader.pos = offset;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.text, msg.type);
    try testing.expectEqualStrings("Hello", msg.data);
}

test "Reader.nextMessage: interleaved control during fragmentation" {
    var embedded_buf: [256]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // Fragment 1: text FIN=0 "Hel"
    const f1 = buildMaskedFrame(&frame_buf, .text, false, "Hel", mask_key);
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    // Interleaved ping
    const f2 = buildMaskedFrame(&frame_buf, .ping, true, "p", mask_key);
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    // Fragment 2: continuation FIN=1 "lo"
    const f3 = buildMaskedFrame(&frame_buf, .continuation, true, "lo", mask_key);
    @memcpy(embedded_buf[offset..][0..f3.len], f3);
    offset += f3.len;

    reader.pos = offset;

    // First: should get the ping control frame
    const msg1 = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.ping, msg1.type);
    try testing.expectEqualStrings("p", msg1.data);

    // Second: should get the reassembled message
    const msg2 = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.text, msg2.type);
    try testing.expectEqualStrings("Hello", msg2.data);

    // No more
    try testing.expect((try reader.nextMessage()) == null);
}

test "Reader.nextMessage: readSlice grows when full" {

    // Tiny inline buffer that will fill up
    var embedded_buf: [16]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    // Fill the buffer completely
    reader.pos = 16;

    // readSlice should compact/grow instead of failing
    const slice = try reader.readSlice();
    try testing.expect(slice.len > 0);
}

test "Reader.nextMessage: readSlice compacts early when tail is tiny" {
    var embedded_buf: [64]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    // Remaining tail = 2 bytes, reclaimable consumed prefix = 40 bytes.
    // Heuristic should compact before we hit a full buffer.
    reader.start = 40;
    reader.pos = 62;

    const slice = try reader.readSlice();
    try testing.expectEqual(@as(usize, 0), reader.start);
    try testing.expectEqual(@as(usize, 22), reader.pos);
    try testing.expectEqual(@as(usize, 42), slice.len);
}

test "Reader.nextMessage: readSlice does not compact early when tail is ample" {
    var embedded_buf: [64]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    // start >= live_len holds (40 >= 10), but tail (14 bytes) is not tiny,
    // so early compaction should not run.
    reader.start = 40;
    reader.pos = 50;

    const slice = try reader.readSlice();
    try testing.expectEqual(@as(usize, 40), reader.start);
    try testing.expectEqual(@as(usize, 50), reader.pos);
    try testing.expectEqual(@as(usize, 14), slice.len);
}

test "Reader.nextMessage: readSlice compacts before growing" {
    var embedded_buf: [16]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    // Consume half the buffer so start > 0, then fill to end
    reader.start = 8;
    reader.pos = 16;

    // readSlice should compact first (moving 8 bytes of data to front),
    // giving us 8 free bytes without needing to grow
    const slice = try reader.readSlice();
    try testing.expect(slice.len == 8);
    try testing.expectEqual(@as(usize, 0), reader.start);
    try testing.expectEqual(@as(usize, 8), reader.pos);
}

test "Reader.nextMessage: protocol error on nested fragments" {
    var embedded_buf: [256]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // Fragment 1: text FIN=0 "A"
    const f1 = buildMaskedFrame(&frame_buf, .text, false, "A", mask_key);
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    // Another text FIN=0 "B" — protocol violation (nested fragment)
    const f2 = buildMaskedFrame(&frame_buf, .text, false, "B", mask_key);
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    reader.pos = offset;

    // First call consumes fragment start, second should error
    try testing.expectError(error.ProtocolError, reader.nextMessage());
}

test "Reader.nextMessage: protocol error on unexpected continuation" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;

    // Continuation frame without a preceding fragment start
    const f = buildMaskedFrame(&frame_buf, .continuation, true, "data", mask_key);
    @memcpy(embedded_buf[0..f.len], f);
    reader.pos = f.len;

    try testing.expectError(error.ProtocolError, reader.nextMessage());
}

test "Reader.nextMessage: protocol error on unmasked frame" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    // Build an unmasked text frame manually
    embedded_buf[0] = 0x81; // FIN=1, text
    embedded_buf[1] = 0x05; // MASK=0, len=5
    @memcpy(embedded_buf[2..7], "Hello");
    reader.pos = 7;

    try testing.expectError(error.ProtocolError, reader.nextMessage());
}

test "Reader.nextMessage: message too large" {
    var embedded_buf: [128]u8 = undefined;
    // Very small max message size
    var reader = testReader(&embedded_buf, 10);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;

    // Frame with payload larger than max_message_size
    const f = buildMaskedFrame(&frame_buf, .text, true, "This is too long!", mask_key);
    @memcpy(embedded_buf[0..f.len], f);
    reader.pos = f.len;

    try testing.expectError(error.MessageTooBig, reader.nextMessage());
}

test "Reader.nextMessage: multiple frames in buffer" {
    var embedded_buf: [256]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // Frame 1: text "Hi"
    const f1 = buildMaskedFrame(&frame_buf, .text, true, "Hi", mask_key);
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    // Frame 2: text "Bye"
    const f2 = buildMaskedFrame(&frame_buf, .text, true, "Bye", mask_key);
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    reader.pos = offset;

    // First message
    const msg1 = (try reader.nextMessage()).?;
    try testing.expectEqualStrings("Hi", msg1.data);

    // Second message
    const msg2 = (try reader.nextMessage()).?;
    try testing.expectEqualStrings("Bye", msg2.data);

    // No more
    try testing.expect((try reader.nextMessage()) == null);
}

test "Reader.nextMessage: pong control frame" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    var frame_buf: [64]u8 = undefined;
    const f = buildMaskedFrame(&frame_buf, .pong, true, "pong", .{ 0x11, 0x22, 0x33, 0x44 });
    @memcpy(embedded_buf[0..f.len], f);
    reader.pos = f.len;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.pong, msg.type);
    try testing.expectEqualStrings("pong", msg.data);
}

test "Reader.nextMessage: empty buffer returns null" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    try testing.expect((try reader.nextMessage()) == null);
}

test "Reader.nextMessage: fragment reassembly (binary)" {
    var embedded_buf: [256]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    const part1 = [_]u8{ 0xDE, 0xAD };
    const part2 = [_]u8{ 0xBE, 0xEF };

    // Fragment 1: binary FIN=0
    const f1 = buildMaskedFrame(&frame_buf, .binary, false, &part1, mask_key);
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    // Fragment 2: continuation FIN=1
    const f2 = buildMaskedFrame(&frame_buf, .continuation, true, &part2, mask_key);
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    reader.pos = offset;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.binary, msg.type);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, msg.data);
}

test "Reader.nextMessage: three-fragment reassembly" {
    var embedded_buf: [256]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // Fragment 1: text FIN=0 "He"
    const f1 = buildMaskedFrame(&frame_buf, .text, false, "He", mask_key);
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    // Fragment 2: continuation FIN=0 "ll"
    const f2 = buildMaskedFrame(&frame_buf, .continuation, false, "ll", mask_key);
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    // Fragment 3: continuation FIN=1 "o"
    const f3 = buildMaskedFrame(&frame_buf, .continuation, true, "o", mask_key);
    @memcpy(embedded_buf[offset..][0..f3.len], f3);
    offset += f3.len;

    reader.pos = offset;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.text, msg.type);
    try testing.expectEqualStrings("Hello", msg.data);

    try testing.expect((try reader.nextMessage()) == null);
}

test "Reader.nextMessage: fragmented message exceeds max size" {
    var embedded_buf: [256]u8 = undefined;
    // max_message_size = 8, so fragments totalling more than 8 should fail
    var reader = testReader(&embedded_buf, 8);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // Fragment 1: 5 bytes
    const f1 = buildMaskedFrame(&frame_buf, .text, false, "AAAAA", mask_key);
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    // Fragment 2: 5 more bytes — total 10, exceeds max of 8
    const f2 = buildMaskedFrame(&frame_buf, .continuation, true, "BBBBB", mask_key);
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    reader.pos = offset;

    try testing.expectError(error.MessageTooBig, reader.nextMessage());
}

test "Reader.nextMessage: multiple fragmented messages in sequence" {
    var embedded_buf: [512]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // First fragmented message: "AB"
    const f1 = buildMaskedFrame(&frame_buf, .text, false, "A", mask_key);
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    const f2 = buildMaskedFrame(&frame_buf, .continuation, true, "B", mask_key);
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    // Second fragmented message: "CD"
    const f3 = buildMaskedFrame(&frame_buf, .binary, false, "C", mask_key);
    @memcpy(embedded_buf[offset..][0..f3.len], f3);
    offset += f3.len;

    const f4 = buildMaskedFrame(&frame_buf, .continuation, true, "D", mask_key);
    @memcpy(embedded_buf[offset..][0..f4.len], f4);
    offset += f4.len;

    reader.pos = offset;

    // First fragmented message
    const msg1 = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.text, msg1.type);
    try testing.expectEqualStrings("AB", msg1.data);

    // Second fragmented message
    const msg2 = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.binary, msg2.type);
    try testing.expectEqualStrings("CD", msg2.data);

    try testing.expect((try reader.nextMessage()) == null);
}

test "Reader.nextMessage: reset cleans up active fragments" {
    var embedded_buf: [256]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;

    // Start a fragment but don't finish it
    const f1 = buildMaskedFrame(&frame_buf, .text, false, "partial", mask_key);
    @memcpy(embedded_buf[0..f1.len], f1);
    reader.pos = f1.len;

    // Process the first fragment (sets fragment_opcode, appends to fragment_buf)
    try testing.expect((try reader.nextMessage()) == null);
    try testing.expect(reader.fragment_opcode != null);

    // Reset should clean up fragment state
    reader.reset();

    try testing.expectEqual(@as(?types.Opcode, null), reader.fragment_opcode);
    try testing.expectEqual(@as(usize, 0), reader.fragment_buf.items.len);
    try testing.expectEqual(reader.embedded_buf.ptr, reader.buf.ptr);
    try testing.expectEqual(@as(usize, 0), reader.pos);
    try testing.expectEqual(@as(usize, 0), reader.start);
}

test "Reader.nextMessage: interleaved close during fragmentation" {
    var embedded_buf: [256]u8 = undefined;
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // Fragment 1: text FIN=0 "Hel"
    const f1 = buildMaskedFrame(&frame_buf, .text, false, "Hel", mask_key);
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    // Interleaved close (status 1000)
    const close_payload = [_]u8{ 0x03, 0xE8 };
    const f2 = buildMaskedFrame(&frame_buf, .close, true, &close_payload, mask_key);
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    // Fragment 2: continuation FIN=1 "lo"
    const f3 = buildMaskedFrame(&frame_buf, .continuation, true, "lo", mask_key);
    @memcpy(embedded_buf[offset..][0..f3.len], f3);
    offset += f3.len;

    reader.pos = offset;

    // First: should get the close control frame
    const msg1 = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.close, msg1.type);
    try testing.expectEqualSlices(u8, &close_payload, msg1.data);

    // Second: should get the reassembled message
    const msg2 = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.text, msg2.type);
    try testing.expectEqualStrings("Hello", msg2.data);

    try testing.expect((try reader.nextMessage()) == null);
}

test "Reader: set pos for pre-loaded data" {
    var embedded_buf: [128]u8 = undefined;
    @memcpy(embedded_buf[0..5], "hello");
    var reader = testReader(&embedded_buf, 1024);
    defer reader.deinit();

    reader.pos = 5;
    try testing.expectEqual(@as(usize, 5), reader.pos);
    try testing.expectEqualStrings("hello", reader.data());
}

// --- Reader(.client) tests ---

const ClientReader = Reader(.client);

/// Build an unmasked WebSocket frame into `out`. Returns the slice of `out` that was written.
fn buildUnmaskedFrame(out: []u8, opcode: types.Opcode, fin: bool, payload: []const u8) []u8 {
    const header_len = writeFrameHeader(out, opcode, fin, payload.len, false);
    @memcpy(out[header_len..][0..payload.len], payload);
    return out[0 .. header_len + payload.len];
}

fn testClientReader(embedded_buf: []u8, max_msg: usize) ClientReader {
    return ClientReader.init(embedded_buf, testing.allocator, max_msg);
}

test "Reader(.client): single unmasked text frame" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testClientReader(&embedded_buf, 1024);
    defer reader.deinit();

    var frame_buf: [64]u8 = undefined;
    const f = buildUnmaskedFrame(&frame_buf, .text, true, "Hello");
    @memcpy(embedded_buf[0..f.len], f);
    reader.pos = f.len;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.text, msg.type);
    try testing.expectEqualStrings("Hello", msg.data);
    try testing.expect((try reader.nextMessage()) == null);
}

test "Reader(.client): rejects masked frame from server" {
    var embedded_buf: [128]u8 = undefined;
    var reader = testClientReader(&embedded_buf, 1024);
    defer reader.deinit();

    // Build a masked frame — invalid for server-to-client
    var frame_buf: [64]u8 = undefined;
    const f = buildMaskedFrame(&frame_buf, .text, true, "Hello", .{ 0x37, 0xFA, 0x21, 0x3D });
    @memcpy(embedded_buf[0..f.len], f);
    reader.pos = f.len;

    try testing.expectError(error.ProtocolError, reader.nextMessage());
}

test "Reader(.client): fragment reassembly with unmasked frames" {
    var embedded_buf: [256]u8 = undefined;
    var reader = testClientReader(&embedded_buf, 1024);
    defer reader.deinit();

    var frame_buf: [64]u8 = undefined;
    var offset: usize = 0;

    // Fragment 1: text FIN=0 "Hel"
    const f1 = buildUnmaskedFrame(&frame_buf, .text, false, "Hel");
    @memcpy(embedded_buf[offset..][0..f1.len], f1);
    offset += f1.len;

    // Fragment 2: continuation FIN=1 "lo"
    const f2 = buildUnmaskedFrame(&frame_buf, .continuation, true, "lo");
    @memcpy(embedded_buf[offset..][0..f2.len], f2);
    offset += f2.len;

    reader.pos = offset;

    const msg = (try reader.nextMessage()).?;
    try testing.expectEqual(types.Message.Type.text, msg.type);
    try testing.expectEqualStrings("Hello", msg.data);
}

test "Reader: payload exactly at max_message_size via read loop" {
    const max_msg_size = 100;
    const payload = "A" ** max_msg_size;
    const mask_key = [_]u8{ 0x37, 0xFA, 0x21, 0x3D };

    // Build the full wire frame (header + mask + payload)
    var wire_buf: [256]u8 = undefined;
    const wire_frame = buildMaskedFrame(&wire_buf, .text, true, payload, mask_key);
    // Sanity: wire frame is larger than max_message_size due to header overhead
    try testing.expect(wire_frame.len > max_msg_size);

    // Small embedded buffer forces growth during the read loop
    var embedded_buf: [32]u8 = undefined;
    var reader = testReader(&embedded_buf, max_msg_size);
    defer reader.deinit();

    // Simulate the real read loop: readSlice → copy chunk → advancePos → nextMessage
    var wire_offset: usize = 0;
    while (wire_offset < wire_frame.len) {
        const dest = try reader.readSlice();
        const remaining = wire_frame.len - wire_offset;
        const chunk = @min(dest.len, remaining);
        @memcpy(dest[0..chunk], wire_frame[wire_offset..][0..chunk]);
        reader.advancePos(chunk);
        wire_offset += chunk;

        if (try reader.nextMessage()) |msg| {
            try testing.expectEqual(types.Message.Type.text, msg.type);
            try testing.expectEqualStrings(payload, msg.data);
            return; // success
        }
    }
    // If we get here, all wire data was fed but no message was produced
    return error.TestUnexpectedResult;
}
