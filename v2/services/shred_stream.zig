//! Streams shreds from an offline Agave ledger into the shred receiver's input ring.

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");
const shred_stream = @import("shred_stream");
const shred_stream_api = @import("shred_stream_api");

comptime {
    _ = start;
}

pub const name = .shred_stream;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.shred_stream.ReadOnly;
pub const ReadWrite = services.shred_stream.ReadWrite;

var scratch_memory: [128 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    var arg_buf: [shred_stream_api.Args.max_args][]const u8 = undefined;
    const args = try ro.args.slices(&arg_buf);

    var fba: std.heap.FixedBufferAllocator = .init(&scratch_memory);
    var packet_writer = rw.shred_pair.recv.get(.writer);

    const inputs: shred_stream.Inputs = try .init(fba.allocator(), logger, args);

    try shred_stream.run(fba.allocator(), logger, &packet_writer, inputs);

    logger.info().logf("shred-stream service finished", .{});
    while (true) try runner.activity.signalIdleSpinning();
}
