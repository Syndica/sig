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

pub const DUMP_INTERVAL = Duration.fromSecs(10);

pub const GossipDumpService = struct {
    allocator: Allocator,
    logger: Logger(@typeName(Self)),
    gossip_table_rw: *RwMux(GossipTable),
    exit_condition: ExitCondition,

    const Self = @This();

    pub fn run(self: Self) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "gossip GossipDumpService.run" });
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
        const now = std.time.timestamp();
        const filename_bounded = sig.utils.fmt.boundedFmt(
            "gossip-dump-{d:0>2}:{d:0>2}:{d:0>2}.csv",
            secondsToHourMinuteSeconds(@intCast(now)),
        );

        const file = try dir.createFile(filename_bounded.constSlice(), .{});
        defer file.close();

        var bws = std.io.bufferedWriter(file.writer());
        defer bws.flush() catch |err| self.logger.warn().logf(
            "{s}: Failed to flush gossip dump in defer.",
            .{@errorName(err)},
        );
        const writer = bws.writer();

        const Row = struct {
            message_type: sig.gossip.data.GossipDataTag,
            pubkey: sig.core.Pubkey,
            hash: sig.core.Hash,
            wallclock: u64,
            shred_version: ?u16,
            gossip_addr: ?sig.net.SocketAddr,
            extra: Extra,

            const Extra = union(enum) {
                null,
                legacy_contact_info: struct {
                    tpu: ?sig.net.SocketAddr,
                    tpu_vote: ?sig.net.SocketAddr,
                },
                contact_info: struct {
                    tpu: ?sig.net.SocketAddr,
                    tpu_vote: ?sig.net.SocketAddr,
                    tpu_quic: ?sig.net.SocketAddr,
                    tpu_vote_quic: ?sig.net.SocketAddr,
                },
            };
        };

        // output csv header
        inline for (@typeInfo(Row).@"struct".fields, 0..) |s_field, i| {
            if (i != 0) try writer.writeByte(',');
            try writer.writeAll(s_field.name);
        }
        try writer.writeByte('\n');

        {
            const gossip_table, var gossip_table_lg = self.gossip_table_rw.readWithLock();
            defer gossip_table_lg.unlock();

            const table_len = gossip_table.store.count();

            self.logger.info().logf("gossip table size at {}s: {}", .{
                now -| start_time,
                table_len,
            });

            // write records to string
            var gossip_iter = gossip_table.store.iterator();
            while (gossip_iter.next()) |entry| {
                const gossip_versioned_data = entry.getVersionedData();
                const val: SignedGossipData = gossip_versioned_data.signedData();

                const row: Row = .{
                    .message_type = val.data,
                    .pubkey = val.id(),
                    .hash = gossip_versioned_data.metadata.value_hash,
                    .wallclock = val.wallclock(),
                    .shred_version = val.data.shredVersion(),
                    .gossip_addr = val.data.gossipAddr(),
                    .extra = switch (val.data) {
                        .LegacyContactInfo => |lci| .{
                            .legacy_contact_info = .{
                                .tpu = lci.tpu,
                                .tpu_vote = lci.tpu_vote,
                            },
                        },
                        .ContactInfo => |ci| .{
                            .contact_info = .{
                                .tpu = ci.getSocket(.tpu),
                                .tpu_vote = ci.getSocket(.tpu_vote),
                                .tpu_quic = ci.getSocket(.tpu_quic),
                                .tpu_vote_quic = ci.getSocket(.tpu_vote_quic),
                            },
                        },
                        else => .null,
                    },
                };
                inline for (@typeInfo(Row).@"struct".fields, 0..) |s_field, i| {
                    const field_value = @field(row, s_field.name);

                    if (i != 0) try writer.writeByte(',');
                    switch (s_field.type) {
                        sig.gossip.data.GossipDataTag,
                        => try writer.print("{s}", .{@tagName(field_value)}),

                        sig.core.Pubkey,
                        sig.core.Hash,
                        => try writer.print("{f}", .{field_value}),

                        ?sig.net.SocketAddr,
                        => try writer.print("{?f}", .{field_value}),

                        u64 => try writer.print("{d}", .{field_value}),
                        ?u16 => try writer.print("{?d}", .{field_value}),

                        Row.Extra => switch (field_value) {
                            .null => try writer.writeAll("null&null&null&null"),
                            .legacy_contact_info => |lci| try writer.print(
                                "{?f}&{?f}&null&null",
                                .{ lci.tpu, lci.tpu_vote },
                            ),
                            .contact_info => |ci| try writer.print(
                                "{?f}&{?f}&{?f}&{?f}",
                                .{ ci.tpu, ci.tpu_vote, ci.tpu_quic, ci.tpu_vote_quic },
                            ),
                        },
                        else => @compileError("Unhandled " ++ @typeName(s_field.type)),
                    }
                }
                try writer.writeByte('\n');
            }
        }

        try bws.flush();
    }
};

fn secondsToHourMinuteSeconds(secs: u64) struct { u5, u6, u6 } {
    const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const day_secs = epoch_secs.getDaySeconds();
    return .{
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    };
}
