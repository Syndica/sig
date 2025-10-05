const std = @import("std");
const sig = @import("../sig.zig");
const base58 = @import("base58");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipTable = sig.gossip.table.GossipTable;
const Duration = sig.time.Duration;
const Logger = sig.trace.log.Logger;
const RwMux = sig.sync.mux.RwMux;
const ExitCondition = sig.sync.ExitCondition;

const BASE58_TABLE = base58.Table.BITCOIN;

pub const DUMP_INTERVAL = Duration.fromSecs(10);

pub const GossipDumpService = struct {
    allocator: Allocator,
    logger: Logger(@typeName(GossipDumpService)),
    gossip_table_rw: *RwMux(GossipTable),
    exit_condition: ExitCondition,

    pub fn run(self: GossipDumpService) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "gossip GossipDumpService.run" });
        defer zone.deinit();

        defer {
            // this should be the last service in the chain,
            // but we still kick off anything after it just in case
            self.exit_condition.afterExit();
        }

        const start_time = std.time.timestamp();

        var directory_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const directory_path = try std.fmt.bufPrint(
            &directory_path_buffer,
            "gossip-dumps/{d}",
            .{start_time},
        );

        var dir = try std.fs.cwd().makeOpenPath(directory_path, .{});
        defer dir.close();

        while (self.exit_condition.shouldRun()) {
            try self.dumpGossip(dir, start_time);
            std.Thread.sleep(DUMP_INTERVAL.asNanos());
        }
    }

    fn dumpGossip(self: *const GossipDumpService, dir: std.fs.Dir, start_time: i64) !void {
        const data = blk: {
            var gossip_table_lock = self.gossip_table_rw.read();
            defer gossip_table_lock.unlock();
            const gossip_table: *const GossipTable = gossip_table_lock.get();

            // allocate buffer to write records
            const table_length = gossip_table.store.count();

            var buffer: std.Io.Writer.Allocating = .init(self.allocator);
            defer buffer.deinit();
            try buffer.ensureTotalCapacity((table_length + 1) * 200);

            const writer = &buffer.writer;

            // write records to string
            var iterator = gossip_table.store.iterator();
            while (iterator.next()) |entry| {
                const gossip_versioned_data = entry.getVersionedData();
                const val: SignedGossipData = gossip_versioned_data.signedData();

                var encoded_buf: [52]u8 = undefined;
                const encoded_len = BASE58_TABLE.encode(
                    &encoded_buf,
                    &gossip_versioned_data.metadata.value_hash.data,
                );
                const encoded = encoded_buf[0..encoded_len];

                try writer.print(
                    "{t},{f},{s},{},",
                    .{ val.data, val.id(), encoded, val.wallclock() },
                );
                if (val.data.gossipAddr()) |addr| {
                    try writer.print("{f}", .{addr.toAddress()});
                }
                try writer.writeByte(',');
                if (val.data.shredVersion()) |shred| {
                    try writer.print("{}", .{shred});
                }
                try writer.writeByte('\n');
            }

            break :blk .{
                try buffer.toOwnedSlice(),
                table_length,
            };
        };
        const buffer, const length = data;
        defer self.allocator.free(buffer);

        // create file
        const now = std.time.timestamp();

        var filename_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const filename = try std.fmt.bufPrint(&filename_buffer, "gossip-dump-{d}.csv", .{now});

        var file = try dir.createFile(filename, .{});
        defer file.close();

        // output results
        try file.writeAll("message_type,pubkey,hash,wallclock,gossip_addr,shred_version\n");
        try file.writeAll(buffer);
        self.logger.info().logf("gossip table size at {}s: {}", .{
            now -| start_time,
            length,
        });
    }
};
