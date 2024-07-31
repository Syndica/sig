const std = @import("std");
const sig = @import("../lib.zig");
const bincode = sig.bincode;

// needed for mkfifo syscall
const c = @cImport({
    @cInclude("sys/types.h");
    @cInclude("sys/stat.h");
});

const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

pub const Payload = struct {
    data_len: u64,
    data: Data,

    pub const Data = struct {
        slot: Slot,
        pubkeys: []Pubkey,
        accounts: []Account,
    };
};

pub const GeyserWriter = struct {
    // used to allocate a buf for serialization
    allocator: std.mem.Allocator,
    file: std.fs.File,
    buf: []u8,

    const Self = @This();

    /// initializes a linux pipe to stream data to
    pub fn init(allocator: std.mem.Allocator, pipe_path: []const u8) !Self {
        const file = try openPipe(pipe_path);
        const buf = try allocator.alloc(u8, 1 << 30); // 1GB
        return .{ .file = file, .allocator = allocator, .buf = buf };
    }

    pub fn deinit(self: Self) void {
        self.file.close();
        self.allocator.free(self.buf);
    }

    /// streams a batch of accounts to the pipe using bincode serialization.
    /// returns the number of bytes wrote.
    pub fn write(
        self: *Self,
        slot: Slot,
        accounts: []Account,
        pubkeys: []Pubkey,
    ) !u64 {
        const data = Payload.Data{ .slot = slot, .pubkeys = pubkeys, .accounts = accounts };
        const data_len = bincode.sizeOf(data, .{});
        const payload = Payload{ .data_len = data_len, .data = data };

        // ensure we have enough space in the buffer
        const size = bincode.sizeOf(payload, .{});
        if (size > self.buf.len) {
            const new_buf = try self.allocator.alloc(u8, size);
            self.allocator.free(self.buf);
            self.buf = new_buf;
        }

        const written_buf = try bincode.writeToSlice(self.buf, payload, .{});
        _ = try self.file.writeAll(written_buf);

        return written_buf.len;
    }
};

pub const GeyserReader = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    // read from pipe into this
    io_buf: []u8,
    // use this for bincode allocations (and is the underlying memory for fb_allocator)
    bincode_buf: []u8,
    // NOTE: not thread-safe
    bincode_allocator: std.heap.FixedBufferAllocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pipe_path: []const u8) !Self {
        const file = try openPipe(pipe_path);
        // TODO(x19): make config
        const io_buf = try allocator.alloc(u8, 1 << 18); // 256kb
        errdefer allocator.free(io_buf);

        const bincode_buf = try allocator.alloc(u8, 1 << 30); // 1GB
        errdefer allocator.free(bincode_buf);
        const fb_allocator = std.heap.FixedBufferAllocator.init(bincode_buf);

        return .{
            .file = file,
            .allocator = allocator,
            .io_buf = io_buf,
            .bincode_buf = bincode_buf,
            .bincode_allocator = fb_allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.file.close();
        self.allocator.free(self.io_buf);
        self.allocator.free(self.bincode_buf);
    }

    /// this should be called after each payload so we dont run OOM.
    /// NOTE: bincode.free doesnt work with FBA since alloc and dealloc occurs as (field1 -> fieldN)
    /// so we would need dealloc to happen as (fieldN -> field1) so we have to drop the
    /// entire FBA
    /// TODO(x19): improve this
    pub fn resetMemory(self: *Self) void {
        self.bincode_allocator.reset();
    }

    /// reads a payload from the pipe and returns the total bytes read with the data
    pub fn readPayload(self: *Self) !struct { u64, Payload.Data } {
        const data_size = try self.readType(u64, 8);
        const data = try self.readType(Payload.Data, data_size);
        return .{ 8 + data_size, data };
    }

    /// reads size number of bytes from the pipe and deserializes it into T.
    /// size is required to ensure we read unknown-length data slices into our buf.
    pub fn readType(self: *Self, comptime T: type, size: u64) !T {
        // make sure we have enough space in the buffer
        if (size > self.io_buf.len) {
            const new_buf = try self.allocator.alloc(u8, size);
            self.allocator.free(self.io_buf);
            self.io_buf = new_buf;
        }

        const bytes_read = try self.file.readAll(self.io_buf[0..size]);
        if (bytes_read != size) {
            if (bytes_read == 0) {
                return error.PipeClosed;
            } else {
                std.debug.print("read {} bytes, expected {}\n", .{ bytes_read, size });
                return error.ReadPipeFailed;
            }
        }
        const data = try bincode.readFromSlice(self.bincode_allocator.allocator(), T, self.io_buf[0..size], .{});
        return data;
    }
};

pub fn openPipe(pipe_path: []const u8) !std.fs.File {
    // setup the pipe
    const rc = c.mkfifo(@ptrCast(pipe_path), c.S_IRWXU);
    if (rc != 0) {
        const err = std.posix.errno(rc);
        switch (err) {
            // if the pipe already exists, thats ok
            .EXIST => {},
            else => {
                std.debug.print("Failed to create pipe: {}\n", .{err});
                return error.FailedToCreatePipe;
            },
        }
    }

    const file = try std.fs.cwd().openFile(pipe_path, .{ .mode = .read_write });
    return file;
}

test "streaming accounts" {
    const allocator = std.testing.allocator;
    const batch_len = 2;

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    // generate some data
    const accounts = try allocator.alloc(Account, batch_len);
    defer {
        for (accounts) |*account| account.deinit(allocator);
        allocator.free(accounts);
    }
    const pubkeys = try allocator.alloc(Pubkey, batch_len);
    defer allocator.free(pubkeys);

    for (0..batch_len) |i| {
        accounts[i] = try Account.random(allocator, rng, 10);
        pubkeys[i] = Pubkey.random(rng);
    }

    // setup writer
    var stream_writer = try GeyserWriter.init(allocator, "test_data/stream_test.pipe");
    defer stream_writer.deinit();

    // setup reader
    var stream_reader = try GeyserReader.init(allocator, "test_data/stream_test.pipe");
    defer stream_reader.deinit();

    // write to the pipe
    _ = try stream_writer.write(100, accounts, pubkeys);

    // read from the pipe
    _, const data = try stream_reader.readPayload();

    const expected_data = Payload.Data{
        .accounts = accounts,
        .pubkeys = pubkeys,
        .slot = 100,
    };
    try std.testing.expectEqualDeep(expected_data, data);
    stream_reader.resetMemory();

    // write to the pipe twice
    // #1
    _ = try stream_writer.write(100, accounts, pubkeys);

    const accounts2 = try allocator.alloc(Account, batch_len);
    defer {
        for (accounts2) |*account| account.deinit(allocator);
        allocator.free(accounts2);
    }
    const pubkeys2 = try allocator.alloc(Pubkey, batch_len);
    defer allocator.free(pubkeys2);
    for (0..batch_len) |i| {
        accounts2[i] = try Account.random(allocator, rng, 10);
        pubkeys2[i] = Pubkey.random(rng);
    }
    // #2
    _ = try stream_writer.write(100, accounts2, pubkeys2);

    // first payload matches
    _, const data2 = try stream_reader.readPayload();
    const expected_data2 = Payload.Data{
        .accounts = accounts,
        .pubkeys = pubkeys,
        .slot = 100,
    };
    try std.testing.expectEqualDeep(expected_data2, data2);
    stream_reader.resetMemory();

    // second payload matches
    _, const data3 = try stream_reader.readPayload();
    const expected_data3 = Payload.Data{
        .accounts = accounts2,
        .pubkeys = pubkeys2,
        .slot = 100,
    };
    try std.testing.expectEqualDeep(expected_data3, data3);
    stream_reader.resetMemory();
}

pub const BenchmarkAccountStream = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 1;

    pub const BenchmarkArgs = struct {
        name: []const u8 = "",
        n_accounts: u64,
        data_len: u64,
        slots: u64,
    };

    pub const args = [_]BenchmarkArgs{
        .{
            .name = "accounts_1k_data_len_100",
            .n_accounts = 1_000,
            .data_len = 100,
            .slots = 100,
        },
        .{
            .name = "accounts_1k_data_len_200",
            .n_accounts = 1_000,
            .data_len = 200,
            .slots = 100,
        },
        .{
            .name = "accounts_1k_data_len_200",
            .n_accounts = 1_000,
            .data_len = 400,
            .slots = 100,
        },
        .{
            .name = "accounts_1k_data_len_1k",
            .n_accounts = 1_000,
            .data_len = 1_000,
            .slots = 100,
        },
        .{
            .name = "accounts_10k_data_len_100",
            .n_accounts = 10_000,
            .data_len = 100,
            .slots = 100,
        },
    };

    pub fn benchmarkAccountStreaming(bench_args: BenchmarkArgs) !u64 {
        const allocator = std.heap.page_allocator;

        var random = std.rand.DefaultPrng.init(19);
        const rng = random.random();

        // generate some data
        const accounts = try allocator.alloc(Account, bench_args.n_accounts);
        defer {
            for (accounts) |*account| {
                account.deinit(allocator);
            }
            allocator.free(accounts);
        }
        const pubkeys = try allocator.alloc(Pubkey, bench_args.n_accounts);
        defer allocator.free(pubkeys);

        for (0..bench_args.n_accounts) |i| {
            accounts[i] = try Account.random(allocator, rng, bench_args.data_len);
            pubkeys[i] = Pubkey.random(rng);
        }

        // setup writer
        var stream_writer = try GeyserWriter.init(allocator, "test_data/bench_test.pipe");
        defer stream_writer.deinit();

        // setup reader
        const stream_reader = try allocator.create(GeyserReader);
        stream_reader.* = try GeyserReader.init(allocator, "test_data/bench_test.pipe");
        defer {
            stream_reader.deinit();
            allocator.destroy(stream_reader);
        }

        const read_handle = try std.Thread.spawn(.{}, readLoop, .{ stream_reader, bench_args.slots });

        var start = try sig.time.Timer.start();
        for (0..bench_args.slots) |slot| {
            _ = try stream_writer.write(slot, accounts, pubkeys);
        }
        // when reader is done reading, we can stop the timer
        read_handle.join();
        const end = start.read().asNanos();

        return end;
    }
};

pub fn readLoop(stream_reader: *GeyserReader, n_payloads: usize) !void {
    var count: usize = 0;
    while (count < n_payloads) {
        _, const payload = try stream_reader.readPayload();

        std.mem.doNotOptimizeAway(payload);
        stream_reader.resetMemory();

        count += 1;
    }
}
