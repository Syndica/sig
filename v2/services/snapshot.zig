const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const tel = lib.telemetry;

const Address = lib.gossip.Address;
const Slot = lib.solana.Slot;
const Hash = lib.solana.Hash;
const IoUring = std.os.linux.IoUring;
const SnapshotSourceRing = lib.snapshot.SnapshotSourceRing;

const MAX_DRAIN: u8 = 64;
const GOSSIP_DRAIN_INTERVAL: std.os.linux.kernel_timespec = .{ .sec = 0, .nsec = 100_000_000 };

const SlotAndHash = struct {
    slot: Slot,
    hash: Hash,

    pub fn eql(self: SlotAndHash, other: SlotAndHash) bool {
        return self.slot == other.slot and std.meta.eql(self.hash, other.hash);
    }
};

const Metrics = struct {
    snapshot_sources_received: tel.Counter,
    snapshot_sources_deduped: tel.Counter,
    snapshot_sources_new: tel.Counter,
    snapshot_sources_updated: tel.Counter,
};

var dedupe_map_buf: [512 * 1024]u8 = @splat(0);
const DedupeMap = std.array_hash_map.ArrayHashMapUnmanaged(
    Address,
    SlotAndHash,
    std.array_hash_map.AutoContext(Address),
    true,
);

const Op = enum(u64) {
    gossip_drain_timeout,
};

const SnapshotService = struct {
    ring: IoUring,
    gossip_iter: *SnapshotSourceRing.Iterator(.reader),
    dedupe_map: *DedupeMap,
    dedupe_alloc: std.mem.Allocator,
    metrics: Metrics,
    logger: tel.Logger("snapshot"),

    fn handleGossipDrainTimeout(self: *SnapshotService) !void {
        var drained: u8 = 0;
        while (drained < MAX_DRAIN) : (drained += 1) {
            const source = self.gossip_iter.next() orelse break;
            self.metrics.snapshot_sources_received.increment(1);

            const key = source.rpc_addr;
            const value: SlotAndHash = .{ .slot = source.slot, .hash = source.hash };

            const gop = try self.dedupe_map.getOrPut(self.dedupe_alloc, key);
            if (!gop.found_existing) {
                gop.value_ptr.* = value;

                self.logger.info().logf(
                    "new snapshot source {f} slot={d} hash={f}",
                    .{ source.rpc_addr, source.slot, source.hash },
                );
                self.metrics.snapshot_sources_new.increment(1);
            } else if (!gop.value_ptr.eql(value)) {
                gop.value_ptr.* = value;

                self.logger.info().logf(
                    "updated snapshot source {f} slot={d} hash={f}",
                    .{ source.rpc_addr, source.slot, source.hash },
                );
                self.metrics.snapshot_sources_updated.increment(1);
            } else {
                self.metrics.snapshot_sources_deduped.increment(1);
            }
        }
        if (drained > 0) self.gossip_iter.markUsed();

        _ = try self.ring.timeout(
            @intFromEnum(Op.gossip_drain_timeout),
            &GOSSIP_DRAIN_INTERVAL,
            0,
            0,
        );
    }

    fn run(self: *SnapshotService) !noreturn {
        // TODO: what to init to?
        var cqes: [256]std.os.linux.io_uring_cqe = undefined;

        // drain messages from gossip service immidiately. This also submits the first timeout for drain interval.
        try self.handleGossipDrainTimeout();

        while (true) {
            _ = try self.ring.submit_and_wait(1);
            const n = try self.ring.copy_cqes(&cqes, 0);

            for (cqes[0..n]) |cqe| {
                const op: Op = @enumFromInt(cqe.user_data);
                switch (op) {
                    .gossip_drain_timeout => try self.handleGossipDrainTimeout(),
                }
            }

            self.ring.cq_advance(n);
        }
    }
};

comptime {
    _ = start;
}

// Note: matches services.zon name
pub const name = .snapshot;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {
    config: *const lib.snapshot.SnapshotConfig,
};

pub const ReadWrite = struct {
    tel: *tel.Region,
    gossip_to_snapshot: *SnapshotSourceRing,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "snapshot");
    const metrics = rw.tel.metricAppender().appendFields(Metrics, .{});
    rw.tel.signalReady();

    const folder_path = ro.config.folder_buffer[0..ro.config.folder_len];
    logger.info().logf("snapshot path {s}", .{folder_path});

    // Create a map for deduping candidate node addresses streaming in from gossip service.
    var dedupe_fba = std.heap.FixedBufferAllocator.init(&dedupe_map_buf);
    var dedupe_map = DedupeMap{};
    var gossip_iter = rw.gossip_to_snapshot.get(.reader);

    var ring = try IoUring.init(256, 0);
    defer ring.deinit();

    var service = SnapshotService{
        .ring = ring,
        .gossip_iter = &gossip_iter,
        .dedupe_map = &dedupe_map,
        .dedupe_alloc = dedupe_fba.allocator(),
        .metrics = metrics,
        .logger = logger,
    };

    try service.run();
}
