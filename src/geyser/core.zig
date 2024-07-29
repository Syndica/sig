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

    const Data = struct {
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
        const buf = try allocator.alloc(u8, 1024);
        return .{ .file = file, .allocator = allocator, .buf = buf };
    }

    pub fn deinit(self: Self) void {
        self.file.close();
        self.allocator.free(self.buf);
    }

    /// streams a batch of accounts to the pipe using bincode serialization
    pub fn write(
        self: *Self,
        slot: Slot,
        accounts: []Account,
        pubkeys: []Pubkey,
    ) !void {
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
    }
};

pub const GeyserReader = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    buf: []u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pipe_path: []const u8) !Self {
        const file = try openPipe(pipe_path);
        const buf = try allocator.alloc(u8, 1024);
        return .{ .file = file, .allocator = allocator, .buf = buf };
    }

    pub fn deinit(self: Self) void {
        self.file.close();
        self.allocator.free(self.buf);
    }

    /// reads a payload from the pipe and returns its data
    pub fn read(self: *Self) !Payload.Data {
        const data_size = try self.readType(u64, 8);
        const data = try self.readType(Payload.Data, data_size);
        return data;
    }

    /// reads size number of bytes from the pipe and deserializes it into T.
    /// size is required to ensure we read unknown-length data slices into our buf.
    pub fn readType(self: *Self, comptime T: type, size: u64) !T {
        // make sure we have enough space in the buffer
        if (size > self.buf.len) {
            const new_buf = try self.allocator.alloc(u8, size);
            self.allocator.free(self.buf);
            self.buf = new_buf;
        }

        const bytes_read = try self.file.readAll(self.buf[0..size]);
        if (bytes_read != size) {
            if (bytes_read == 0) {
                return error.PipeClosed;
            } else {
                std.debug.print("read {} bytes, expected {}\n", .{ bytes_read, size });
                return error.ReadPipeFailed;
            }
        }
        const data = bincode.readFromSlice(self.allocator, T, self.buf[0..size], .{});
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
    try stream_writer.write(100, accounts, pubkeys);

    // read from the pipe
    const data = try stream_reader.read();
    defer bincode.free(allocator, data);

    const expected_data = Payload.Data{
        .accounts = accounts,
        .pubkeys = pubkeys,
        .slot = 100,
    };
    try std.testing.expectEqualDeep(expected_data, data);

    // write to the pipe twice
    // #1
    try stream_writer.write(100, accounts, pubkeys);

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
    try stream_writer.write(100, accounts2, pubkeys2);

    // first payload matches
    const data2 = try stream_reader.read();
    defer bincode.free(allocator, data2);
    const expected_data2 = Payload.Data{
        .accounts = accounts,
        .pubkeys = pubkeys,
        .slot = 100,
    };
    try std.testing.expectEqualDeep(expected_data2, data2);

    // second payload matches
    const data3 = try stream_reader.read();
    defer bincode.free(allocator, data3);
    const expected_data3 = Payload.Data{
        .accounts = accounts2,
        .pubkeys = pubkeys2,
        .slot = 100,
    };
    try std.testing.expectEqualDeep(expected_data3, data3);
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
            try stream_writer.write(slot, accounts, pubkeys);
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
        const data = try stream_reader.read();
        defer bincode.free(stream_reader.allocator, data);

        count += 1;
    }
}
