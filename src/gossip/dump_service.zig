const std = @import("std");
const sig = @import("../sig.zig");
const base58 = @import("base58");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipTable = sig.gossip.table.GossipTable;
const Duration = sig.time.Duration;
const ScopedLogger = sig.trace.log.ScopedLogger;
const RwMux = sig.sync.mux.RwMux;
const ExitCondition = sig.sync.ExitCondition;

pub const DUMP_INTERVAL = Duration.fromSecs(10);

pub const GossipDumpService = struct {
    allocator: Allocator,
    logger: ScopedLogger(@typeName(Self)),
    gossip_table_rw: *RwMux(GossipTable),
    exit_condition: ExitCondition,

    const Self = @This();

    pub fn run(self: Self) !void {
        const zone = tracy.initZone(@src(), .{ .name = "gossip GossipDumpService.run" });
        defer zone.deinit();

        defer {
            // this should be the last service in the chain,
            // but we still kick off anything after it just in case
            self.exit_condition.afterExit();
        }

        const start_time = std.time.timestamp();
        const dir_name_bounded = sig.utils.fmt.boundedFmt("gossip-dumps/{}", .{start_time});

        var dir = try std.fs.cwd().makeOpenPath(dir_name_bounded.constSlice(), .{});
        defer dir.close();

        while (self.exit_condition.shouldRun()) {
            try self.dumpGossip(dir, start_time);
            std.Thread.sleep(DUMP_INTERVAL.asNanos());
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
            const endec = base58.Table.BITCOIN;
            var iterator = gossip_table.store.iterator();
            while (iterator.next()) |entry| {
                const gossip_versioned_data = entry.getVersionedData();
                const val: SignedGossipData = gossip_versioned_data.signedData();

                var encoded_buf: [52]u8 = undefined;
                const encoded_len = endec.encode(
                    &encoded_buf,
                    &gossip_versioned_data.metadata.value_hash.data,
                );
                const encoded = encoded_buf[0..encoded_len];

                try writer.print(
                    "{s},{s},{s},{},",
                    .{ @tagName(val.data), val.id(), encoded, val.wallclock() },
                );
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
