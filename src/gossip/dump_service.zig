const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipTable = sig.gossip.table.GossipTable;
const Duration = sig.time.Duration;
const Logger = sig.trace.log.Logger;
const RwMux = sig.sync.mux.RwMux;

pub const DUMP_INTERVAL = Duration.fromSecs(10);

pub const GossipDumpService = struct {
    allocator: Allocator,
    logger: Logger,
    gossip_table_rw: *RwMux(GossipTable),
    counter: *Atomic(usize),

    const Self = @This();

    pub fn run(self: Self, idx: usize) !void {
        defer {
            // this should be the last service in the chain,
            // but we still kick off anything after it just in case
            self.counter.store(idx + 1, .release);
        }

        const start_time = std.time.timestamp();
        const dir_name_bounded = sig.utils.fmt.boundedFmt("gossip-dumps/{}", .{start_time});

        var dir = try std.fs.cwd().makeOpenPath(dir_name_bounded.constSlice(), .{});
        defer dir.close();

        while (self.counter.load(.acquire) != idx) {
            try self.dumpGossip(dir, start_time);
            std.time.sleep(DUMP_INTERVAL.asNanos());
        }
    }

    fn dumpGossip(self: *const Self, dir: std.fs.Dir, start_time: i64) !void {
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
                try writer.print("{s},{s},{s},{},", .{
                    @tagName(val.data),
                    val.id(),
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
        const filename_bounded = sig.utils.fmt.boundedFmt("gossip-dump-{}.csv", .{now});

        var file = try dir.createFile(filename_bounded.constSlice(), .{});
        defer file.close();

        // output results
        try file.writeAll("message_type,pubkey,hash,wallclock,gossip_addr,shred_version\n");
        try file.writeAll(data.buf[0..data.buf_len]);
        self.logger.info().logf("gossip table size at {}s: {}", .{
            now -| start_time,
            data.table_len,
        });
    }
};
