const std = @import("std");
const SignedGossipData = @import("../gossip/data.zig").SignedGossipData;
const GossipTable = @import("../gossip/table.zig").GossipTable;
const Logger = @import("../trace/log.zig").Logger;
const RwMux = @import("../sync/mux.zig").RwMux;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

pub const GossipDumpService = struct {
    allocator: Allocator,
    logger: Logger,
    gossip_table_rw: *RwMux(GossipTable),
    exit: *Atomic(bool),

    const Self = @This();

    pub fn run(self: Self) !void {
        const start_time = std.time.timestamp();
        const dir = try std.fmt.allocPrint(self.allocator, "gossip-dumps/{}", .{start_time});
        defer self.allocator.free(dir);
        try std.fs.cwd().makePath(dir);
        while (true) {
            if (self.exit.load(.unordered)) return;
            try self.dumpGossip(dir, start_time);
            std.time.sleep(10_000_000_000);
        }
    }

    fn dumpGossip(self: *const Self, dir: []const u8, start_time: i64) !void {
        const data = blk: {
            var gossip_table_lock = self.gossip_table_rw.read();
            defer gossip_table_lock.unlock();
            const gossip_table: *const GossipTable = gossip_table_lock.get();

            // allocate buffer to write records
            const table_len = gossip_table.store.count();
            const buf = try self.allocator.alloc(u8, (1 + table_len) * 200);
            errdefer self.allocator.free(buf);
            var stream = std.io.fixedBufferStream(buf);
            const writer = stream.writer();

            // write records to string
            var encoder_buf: [50]u8 = undefined;
            const base58Encoder = @import("base58-zig").Encoder.init(.{});
            for (gossip_table.store.values()) |gossip_versioned_data| {
                const val: SignedGossipData = gossip_versioned_data.value;
                const size = try base58Encoder.encode(
                    &gossip_versioned_data.value_hash.data,
                    &encoder_buf,
                );
                const pubkey_str = val.id().string();
                const len: usize = if (pubkey_str[43] == 0) 43 else 44;
                try writer.print("{s},{s},{s},{},", .{
                    @tagName(val.data),
                    pubkey_str[0..len],
                    encoder_buf[0..size],
                    val.wallclock(),
                });
                if (val.data.gossipAddr()) |addr| {
                    try addr.toAddress().format("", .{}, writer);
                }
                try writer.writeAll(",");
                if (val.data.shredVersion()) |shred| {
                    try writer.print("{}", .{shred});
                }
                try writer.writeAll("\n");
            }
            break :blk .{ .buf = buf, .buf_len = stream.pos, .table_len = table_len };
        };
        defer self.allocator.free(data.buf);

        // create file
        const now = std.time.timestamp();
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/gossip-dump-{}.csv", .{ dir, now });
        defer self.allocator.free(filename);
        var file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();

        // output results
        try file.writeAll("message_type,pubkey,hash,wallclock,gossip_addr,shred_version\n");
        try file.writeAll(data.buf[0..data.buf_len]);
        self.logger.infof("gossip table size at {}s: {}", .{ now -| start_time, data.table_len });
    }
};
