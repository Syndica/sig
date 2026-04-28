//! This service is intended to be used like a threadpool, supporting:
//! 1) transaction execution
//! 2) proof of history
//! 3) signature verification
//! 4) delta LT
//!

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");

comptime {
    _ = start;
}

pub const name = .exec;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {
    replay_transaction_pool: *const lib.replay.TransactionPool,
    block_pool: *const lib.replay.BlockPool,
};
pub const ReadWrite = struct {
    exec_req_response: *lib.replay.ExecReqResponse,
};

var scratch_memory: [256 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    var request_reader = rw.exec_req_response.request_ring.get(.reader);
    var response_writer = rw.exec_req_response.response_ring.get(.writer);

    while (true) {
        const request: *const lib.replay.ExecRequest = request_reader.next() orelse continue;
        defer request_reader.markUsed();

        const zone = tracy.Zone.init(@src(), .{ .name = "task" });
        defer zone.deinit();
        zone.value(request.task_id);

        switch (request.request_kind) {
            .transaction_execution => {
                const tx_zone = tracy.Zone.init(@src(), .{ .name = "transaction_execution" });
                defer tx_zone.deinit();

                const data = &request.data.transaction_execution;

                var deserialised_buf: [4096]u8 = undefined;
                var deserial_fba: std.heap.FixedBufferAllocator = .init(&deserialised_buf);

                var reader = std.io.Reader.fixed(ro.replay_transaction_pool.indexToConstPtr(data.tx_idx));

                const transaction: lib.solana.transaction.VersionedTransaction =
                    try lib.solana.bincode.read(
                        &deserial_fba,
                        &reader,
                        lib.solana.transaction.VersionedTransaction,
                    );

                std.log.info("transaction: {}", .{transaction});

                const response: *lib.replay.ExecResponse = response_writer.next() orelse @panic("cant write");
                response.* = .{
                    .task_id = request.task_id,
                    .request_kind = .transaction_execution,
                    .data = .{ .transaction_execution = .{ .success = true } },
                };
                response_writer.markUsed();
            },
            .transaction_signature_verify => return error.SigVerifyExecUnimpl,
        }
    }
}
