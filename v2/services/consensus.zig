const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");
const consensus = @import("consensus");
const api = @import("consensus_api");

const BlockRef = api.BlockRef;

comptime {
    _ = start;
}

pub const name = .consensus;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.consensus.ReadOnly;
pub const ReadWrite = services.consensus.ReadWrite;

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    rw.tel.signalReady();

    var input = rw.replay_notifications.in.get(.reader);
    var output = rw.replay_notifications.out.get(.writer);
    var state = try waitForRootInitialized(runner, ro.block_pool, &input);

    task: switch (@as(enum { block_executed, idle }, .idle)) {
        .idle => {
            if (input.peek() != null) continue :task .block_executed;

            while (true) : (std.atomic.spinLoopHint()) {
                if (input.peek() != null) continue :task .block_executed;
                try runner.activity.signalIdleSpinning();
            }
        },
        .block_executed => {
            try runner.activity.signalActive();
            processExecutedBlock(&input, &output, &state);
            continue :task .idle;
        },
    }
}

fn waitForRootInitialized(
    runner: lib.runner.Connection,
    block_pool: *const api.BlockPool,
    input: anytype,
) !consensus.ConsensusState {
    while (true) : (std.atomic.spinLoopHint()) {
        if (receiveRootInitialized(input, block_pool)) |state| return state;
        try runner.activity.signalIdleSpinning();
    }
}

fn receiveRootInitialized(
    input: anytype,
    block_pool: *const api.BlockPool,
) ?consensus.ConsensusState {
    const block = input.next() orelse return null;
    defer input.markUsed();

    return .init(block.*, block_pool);
}

fn processExecutedBlock(
    input: anytype,
    output: anytype,
    state: *consensus.ConsensusState,
) void {
    const block = input.next() orelse unreachable;
    defer input.markUsed();

    const finalized = state.blockConfirmed(block.*) orelse return;
    sendFinalized(output, finalized);
}

fn sendFinalized(output: anytype, block: BlockRef) void {
    // The ring capacity matches BlockPool capacity. Since each live block can
    // produce at most one finalization, replay should always have space here.
    const finalized = output.next() orelse unreachable;
    finalized.* = block;
    output.markUsed();
}

fn blockPoolForConsensusTest(
    pool_buf: *align(@alignOf(api.BlockPool)) [api.BlockPool.size()]u8,
) *api.BlockPool {
    const block_pool: *api.BlockPool = @ptrCast(pool_buf);
    block_pool.init();
    return block_pool;
}

fn setParentForConsensusTest(
    block_pool: *api.BlockPool,
    block: BlockRef,
    parent: ?BlockRef,
) void {
    block.ptr(block_pool).* = .{
        .parent = .init(parent),
        .slot = .null,
    };

    const parent_ref = parent orelse return;
    const parent_block = parent_ref.ptr(block_pool);
    if (parent_block.child == .null) {
        parent_block.child = .init(block);
        return;
    }

    var tail_ref = parent_block.child.opt().?;
    while (true) {
        const tail = tail_ref.ptr(block_pool);
        tail_ref = tail.sibling.opt() orelse {
            tail.sibling = .init(block);
            return;
        };
    }
}

test "services.consensus: receives root and writes finalized block" {
    var pool_buf: [api.BlockPool.size()]u8 align(@alignOf(api.BlockPool)) = undefined;
    const block_pool = blockPoolForConsensusTest(&pool_buf);
    var notifications: api.ReplayNotifications = undefined;
    notifications.init();
    var input_writer = notifications.in.get(.writer);
    var input_reader = notifications.in.get(.reader);
    var output_writer = notifications.out.get(.writer);
    var output_reader = notifications.out.get(.reader);
    const root = BlockRef.fromInt(4);
    const a = BlockRef.fromInt(5);
    const b = BlockRef.fromInt(6);
    const c = BlockRef.fromInt(7);
    const d = BlockRef.fromInt(8);
    setParentForConsensusTest(block_pool, root, null);
    setParentForConsensusTest(block_pool, a, root);
    setParentForConsensusTest(block_pool, b, a);
    setParentForConsensusTest(block_pool, c, b);
    setParentForConsensusTest(block_pool, d, c);

    input_writer.next().?.* = root;
    input_writer.next().?.* = a;
    input_writer.next().?.* = b;
    input_writer.next().?.* = c;
    input_writer.next().?.* = d;
    input_writer.markUsed();

    var state = receiveRootInitialized(&input_reader, block_pool).?;
    processExecutedBlock(&input_reader, &output_writer, &state);
    processExecutedBlock(&input_reader, &output_writer, &state);
    processExecutedBlock(&input_reader, &output_writer, &state);
    processExecutedBlock(&input_reader, &output_writer, &state);
    try std.testing.expectEqual(@as(?*const BlockRef, null), input_reader.peek());

    const finalized = output_reader.next().?;
    try std.testing.expectEqual(a, finalized.*);
    output_reader.markUsed();
    try std.testing.expectEqual(@as(?*const BlockRef, null), output_reader.peek());
}
