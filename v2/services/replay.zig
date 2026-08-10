const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");

const accounts_db = @import("accounts_db_api");

const api = @import("replay_api");
const replay_component = @import("replay");

comptime {
    _ = start;
}

pub const name = .replay;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.replay.ReadOnly;
pub const ReadWrite = services.replay.ReadWrite;

const AccountRef = lib.AccountPool.AccountRef;
const Pubkey = lib.solana.Pubkey;

pub fn serviceMain(runner: lib.runner.Connection, _: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    var fba: std.heap.FixedBufferAllocator = .init(rw.scratch_memory);
    const allocator = fba.allocator();

    var deshredded_iter = rw.deshredded_in.get(.reader);
    var exec_request_sender = rw.exec_req_response.request_ring.get(.writer);
    var exec_response_receiver = rw.exec_req_response.response_ring.get(.reader);

    const Effects = struct {
        rw: ReadWrite,
        deshredded_iter: *@TypeOf(deshredded_iter),
        exec_request_sender: *@TypeOf(exec_request_sender),
        exec_response_receiver: *@TypeOf(exec_response_receiver),

        const Self = @This();

        pub fn nextInput(self: *const Self) replay_component.Input {
            if (self.exec_response_receiver.next()) |response| {
                return .{ .exec_response = response };
            }

            if (self.deshredded_iter.next()) |fec_set| {
                return .{ .fec_set = fec_set };
            }

            return .idle;
        }

        pub fn releaseInput(self: *const Self, input: replay_component.Input) void {
            switch (input) {
                .exec_response => self.exec_response_receiver.markUsed(),
                .fec_set => self.deshredded_iter.markUsed(),
                .idle => {},
            }
        }

        pub fn snapshotMetadata(self: *const Self) *accounts_db.RuntimeMetadata {
            return self.rw.snapshot_metadata_in;
        }

        pub fn fetchRootedAccountBlocking(self: *const Self, key: *const Pubkey) AccountRef {
            var requester = self.rw.account_lookups.in.get(.writer);
            var response_queue = self.rw.account_lookups.out.get(.reader);

            const request_buf = requester.next() orelse @panic("out of space");
            request_buf.* = key.*;
            requester.markUsed();

            // TODO: make account loading asynchronous.
            while (response_queue.peek() == null) : (std.atomic.spinLoopHint()) {}

            const response = response_queue.next().?;
            defer response_queue.markUsed();

            std.debug.assert(response.pubkey.equals(key));
            return response.account_index;
        }

        pub fn blockPool(self: *const Self) *api.BlockPool {
            return self.rw.block_pool;
        }

        pub fn transactionPool(self: *const Self) *api.TransactionPool {
            return self.rw.replay_transaction_pool;
        }

        pub fn execRequestSender(self: *const Self) *@TypeOf(exec_request_sender) {
            return self.exec_request_sender;
        }

        pub fn accountPool(self: *const Self) *lib.AccountPool {
            return self.rw.account_pool;
        }
    };

    const effects: Effects = .{
        .rw = rw,
        .deshredded_iter = &deshredded_iter,
        .exec_request_sender = &exec_request_sender,
        .exec_response_receiver = &exec_response_receiver,
    };

    const Replay = replay_component.Replay(Effects);
    var replay: Replay = try .init(allocator, .{
        .effects = effects,
        .logger = logger,
        .runner = runner,
    });

    // After the slot is supposedly populated, start shred recv (eventually Repair service) on it.

    while (true) : (std.atomic.spinLoopHint()) {
        switch (try replay.poll(logger)) {
            .active => try runner.activity.signalActive(),
            .idle => try runner.activity.signalIdleSpinning(),
        }
    }
}
