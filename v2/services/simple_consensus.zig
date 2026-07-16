const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");

comptime {
    _ = start;
}

pub const name = .simple_consensus;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.simple_consensus.ReadOnly;
pub const ReadWrite = services.simple_consensus.ReadWrite;

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    // Bootstrap: wait for the root slot from snapshot metadata, then find
    // the corresponding block in the pool. Replay populates the block pool
    // during its own bootstrap, so we spin until it's available.
    const root_slot = try rw.snapshot_metadata.getSlotBlocking(runner);
    logger.info().logf("consensus: got root slot {}", .{root_slot});

    const root_block: lib.replay.BlockRef = blk: {
        while (true) {
            for (ro.block_pool.constBuf(), 0..) |node, i| {
                if (node.item.slot.opt()) |s| if (s == root_slot) {
                    break :blk lib.replay.BlockRef.fromInt(@intCast(i));
                };
            }
            try runner.activity.signalIdleSpinning();
        }
    };
    logger.info().logf("consensus: found root block ref {}", .{root_block});

    var consensus: lib.consensus.leaf.SimpleConsensus = .init(ro.block_pool, root_block);
    var exec_results = rw.block_exec_results.get(.reader);
    var finality_writer = rw.block_finality.get(.writer);

    while (true) {
        const result = exec_results.next() orelse {
            try runner.activity.signalIdleSpinning();
            continue;
        };
        defer exec_results.markUsed();
        try runner.activity.signalActive();

        const new_root = consensus.update(result.block_ref, result.passed) catch |err| {
            logger.err().logf("consensus update error: {s} for block {}", .{
                @errorName(err),
                result.block_ref,
            });
            continue;
        } orelse continue;

        const finality = finality_writer.next() orelse {
            logger.err().logf(
                "block_finality ring full, cannot notify replay of finalized block {}",
                .{new_root},
            );
            continue;
        };
        finality.* = new_root;
        finality_writer.markUsed();
        logger.info().logf("finalized block {} (slot {f})", .{
            new_root,
            new_root.constPtr(ro.block_pool).slot,
        });
    }
}
