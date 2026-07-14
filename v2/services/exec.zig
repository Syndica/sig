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
const services = @import("services");
const replay_api = @import("replay_api");

comptime {
    _ = start;
}

pub const name = .exec;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.exec.ReadOnly;
pub const ReadWrite = services.exec.ReadWrite;

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    var request_reader = rw.exec_req_response.request_ring.get(.reader);
    var response_writer = rw.exec_req_response.response_ring.get(.writer);

    var deserialised_buf: [4096]u8 = undefined;
    var deserial_fba: std.heap.FixedBufferAllocator = .init(&deserialised_buf);

    while (true) {
        const request: *const replay_api.ExecRequest = request_reader.next() orelse {
            try runner.activity.signalIdleSpinning();
            continue;
        };
        defer request_reader.markUsed();
        defer deserial_fba.reset();
        try runner.activity.signalActive();

        const zone = tracy.Zone.init(@src(), .{});
        defer zone.deinit();
        zone.name(@tagName(request.request_kind));

        zone.value(request.task_id);

        switch (request.request_kind) {
            .txn_exec => {
                const data = &request.data.txn_exec;

                const slot = data.block_idx.constPtr(ro.block_pool).slot;
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

                const response: *replay_api.ExecResponse = response_writer.next() orelse
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
