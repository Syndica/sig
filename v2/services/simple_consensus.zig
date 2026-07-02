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

    // TODO: real root from snapshot / prior state.
    var consensus: lib.consensus.recurse_tree.SimpleConsensus = .init(ro.block_pool, undefined);
    var exec_results = rw.block_exec_results.get(.reader);
    var finality_writer = rw.block_finality.get(.writer);

    while (true) {
        const result = exec_results.next() orelse {
            try runner.activity.signalIdleSpinning();
            continue;
        };
        defer exec_results.markUsed();
        try runner.activity.signalActive();

        const new_root = consensus.update(result.block_ref, result.passed) orelse continue;

        const finality = finality_writer.next() orelse {
            try runner.activity.signalIdleSpinning();
            continue;
        };
        finality.* = new_root;
        finality_writer.markUsed();
        logger.info().logf("finalized block {}", .{new_root});
    }
}
