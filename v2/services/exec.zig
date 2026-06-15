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

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    _ = runner;
    var request_reader = rw.exec_req_response.request_ring.get(.reader);
    var response_writer = rw.exec_req_response.response_ring.get(.writer);

    var deserialised_buf: [4096]u8 = undefined;
    var deserial_fba: std.heap.FixedBufferAllocator = .init(&deserialised_buf);

    while (true) {
        const request: *const lib.replay.ExecRequest = request_reader.next() orelse continue;
        defer request_reader.markUsed();
        defer deserial_fba.reset();

        const zone = tracy.Zone.init(@src(), .{});
        defer zone.deinit();
        zone.name(@tagName(request.request_kind));

        zone.value(request.task_id);

        switch (request.request_kind) {
            .txn_exec => {
                const data = &request.data.txn_exec;

                const slot = data.block_idx.constPtr(ro.block_pool).?.slot;
                zone.value(slot);
                tracy.plot(u48, "exec slot", @intCast(slot));

                var reader =
                    std.io.Reader.fixed(ro.replay_transaction_pool.indexToConstPtr(data.tx_idx));

                const transaction: lib.solana.transaction.VersionedTransaction =
                    try lib.solana.bincode.read(
                        &deserial_fba,
                        &reader,
                        lib.solana.transaction.VersionedTransaction,
                    );

                _ = transaction;

                const response: *lib.replay.ExecResponse = response_writer.next() orelse
                    @panic("cant write");
                response.* = .{
                    .task_id = request.task_id,
                    .request_kind = .txn_exec,
                    .data = .{
                        .txn_exec = .{
                            .result = .{ .success = true },
                            .block_idx = data.block_idx,
                            .tx_idx = data.tx_idx,
                        },
                    },
                };
                response_writer.markUsed();
            },
            .txn_sig_verify => return error.SigVerifyExecUnimpl,
        }
    }
}
