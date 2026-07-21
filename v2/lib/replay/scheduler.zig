//! Transaction scheduling state for replay.
//!
//! The scheduler owns speculative dependency discovery and determines when
//! transactions are eligible for execution.
//!
//! The current policy is dead simple FIFO with one execution in flight. The API here
//! intentionally uses transaction IDs and readiness/completion events so
//! the implementation can later schedule non-conflicting transactions out of
//! order without changing replay's interface too much.

const std = @import("std");
const lib = @import("../lib.zig");
const alt_resolve = @import("alt_resolve.zig");

const ALTResolver = alt_resolve.ALTResolver;
const BankContext = alt_resolve.BankContext;
const ResolveError = alt_resolve.ResolveError;
const ResolvedTransaction = alt_resolve.ResolvedTransaction;

// TODO: improve documentation.
pub const FIFOScheduler = struct {
    alt_resolver: *ALTResolver,

    entries: [capacity]Entry = @splat(.{}),
    head: usize = 0,
    count: usize = 0,

    next_transaction_id: TransactionId = 1,
    execution_in_flight: bool = false,

    pub const capacity = ALTResolver.MAX_PENDING_TRANSACTIONS;
    pub const TransactionId = u64;

    pub const SubmitParams = struct {
        block_ref: lib.replay.BlockRef,
        tx_ref: lib.replay.TransactionPool.ItemId,
        transaction_index: u32,
        bank_context: BankContext,
    };

    pub const Ready = union(enum) {
        execute: ExecuteTask,
        invalid: InvalidTransaction,
    };

    pub const ExecuteTask = struct {
        id: TransactionId,
        block_ref: lib.replay.BlockRef,
        tx_ref: lib.replay.TransactionPool.ItemId,
        transaction_index: u32,
        dependencies: *const ResolvedTransaction,
    };

    pub const InvalidTransaction = struct {
        id: TransactionId,
        block_ref: lib.replay.BlockRef,
        tx_ref: lib.replay.TransactionPool.ItemId,
        transaction_index: u32,
        err: ResolveError,
    };

    pub const CompletedTransaction = struct {
        block_ref: lib.replay.BlockRef,
        tx_ref: lib.replay.TransactionPool.ItemId,
        transaction_index: u32,
    };

    const Entry = struct {
        id: TransactionId = 0,
        block_ref: lib.replay.BlockRef = undefined,
        tx_ref: lib.replay.TransactionPool.ItemId = undefined,
        transaction_index: u32 = undefined,

        state: State = .free,
        resolver_request: ALTResolver.RequestId = undefined,
        resolved: ResolvedTransaction = undefined,
        resolve_error: ResolveError = undefined,

        const State = enum {
            free,
            resolving,
            awaiting_serialization,
            ready,
            invalid,
            executing,
        };
    };

    pub fn init(resolver: *ALTResolver) FIFOScheduler {
        return .{ .alt_resolver = resolver };
    }

    pub fn canSubmit(self: *const FIFOScheduler) bool {
        return self.count < self.entries.len and
            self.alt_resolver.canSubmit();
    }

    pub fn submit(
        self: *FIFOScheduler,
        params: SubmitParams,
    ) ALTResolver.SubmitError!TransactionId {
        if (!self.canSubmit())
            return error.Full;

        const request_id = try self.alt_resolver.submit(
            params.block_ref,
            params.tx_ref,
            params.bank_context,
        );

        const index = (self.head + self.count) % self.entries.len;
        const id = self.next_transaction_id;
        self.next_transaction_id +%= 1;

        self.entries[index] = .{
            .id = id,
            .block_ref = params.block_ref,
            .tx_ref = params.tx_ref,
            .transaction_index = params.transaction_index,
            .state = .resolving,
            .resolver_request = request_id,
        };

        self.count += 1;
        return id;
    }

    pub fn poll(self: *FIFOScheduler) bool {
        var progressed = self.alt_resolver.drainRootedResults();

        progressed = self.collectALTResolverCompletions() or progressed;
        progressed = self.retrySerializationHead() or progressed;

        // Temporary compatibility rule:
        //
        // Once the FIFO head is ready, stop publishing new Rooted requests.
        // Replay's temporary blocking Phase 2 loader shares the same rings and
        // must wait for existing resolver requests to drain.
        // TODO: document this aspect better.
        if (!self.headIsReady()) {
            progressed =
                self.alt_resolver.drivePendingLookups() or progressed;
        }

        return progressed;
    }

    fn collectALTResolverCompletions(self: *FIFOScheduler) bool {
        var progressed = false;

        for (0..self.count) |offset| {
            const entry = self.entryAt(offset);
            if (entry.state != .resolving)
                continue;

            const completion = self.alt_resolver.peekCompletion(
                entry.resolver_request,
            ) orelse continue;

            switch (completion.result) {
                .resolved => {
                    entry.resolved = completion.transaction;
                    entry.state = .ready;

                    self.alt_resolver.consumeCompletion(entry.resolver_request);
                },

                .needs_serialization => {
                    // Keep the resolver entry alive because retryAlts() reuses
                    // the same pending slot once this transaction reaches the
                    // FIFO serialization boundary.
                    entry.state = .awaiting_serialization;
                },

                .failed => |err| {
                    entry.resolve_error = err;
                    entry.state = .invalid;

                    self.alt_resolver.consumeCompletion(
                        entry.resolver_request,
                    );
                },
            }

            progressed = true;
        }

        return progressed;
    }

    fn retrySerializationHead(self: *FIFOScheduler) bool {
        if (self.execution_in_flight or self.count == 0)
            return false;

        const entry = &self.entries[self.head];
        if (entry.state != .awaiting_serialization)
            return false;

        // Being the FIFO head with no execution in flight establishes the
        // temporary serialization boundary: all earlier writes are visible.
        entry.resolver_request = self.alt_resolver.retryAlts(entry.resolver_request);
        entry.state = .resolving;

        return true;
    }

    pub fn peekReady(self: *FIFOScheduler) ?Ready {
        if (self.execution_in_flight or self.count == 0)
            return null;

        const entry = &self.entries[self.head];

        return switch (entry.state) {
            .ready => {
                // Required only by the temporary blocking account loader.
                if (self.alt_resolver.hasInFlightReads())
                    return null;

                return .{ .execute = .{
                    .id = entry.id,
                    .block_ref = entry.block_ref,
                    .tx_ref = entry.tx_ref,
                    .transaction_index = entry.transaction_index,
                    .dependencies = &entry.resolved,
                } };
            },

            .invalid => .{ .invalid = .{
                .id = entry.id,
                .block_ref = entry.block_ref,
                .tx_ref = entry.tx_ref,
                .transaction_index = entry.transaction_index,
                .err = entry.resolve_error,
            } },

            else => null,
        };
    }

    pub fn markDispatched(
        self: *FIFOScheduler,
        transaction_id: TransactionId,
    ) void {
        std.debug.assert(!self.execution_in_flight);
        std.debug.assert(self.count != 0);

        const entry = &self.entries[self.head];
        std.debug.assert(entry.id == transaction_id);
        std.debug.assert(entry.state == .ready);

        entry.state = .executing;
        self.execution_in_flight = true;
    }

    pub fn complete(
        self: *FIFOScheduler,
        transaction_id: TransactionId,
    ) CompletedTransaction {
        std.debug.assert(self.execution_in_flight);
        std.debug.assert(self.count != 0);

        const entry = &self.entries[self.head];
        std.debug.assert(entry.id == transaction_id);
        std.debug.assert(entry.state == .executing);

        self.execution_in_flight = false;
        return self.popHead();
    }

    pub fn reject(
        self: *FIFOScheduler,
        transaction_id: TransactionId,
    ) CompletedTransaction {
        std.debug.assert(!self.execution_in_flight);
        std.debug.assert(self.count != 0);

        const entry = &self.entries[self.head];
        std.debug.assert(entry.id == transaction_id);
        std.debug.assert(entry.state == .invalid);

        return self.popHead();
    }

    fn popHead(self: *FIFOScheduler) CompletedTransaction {
        const entry = &self.entries[self.head];

        const completed: CompletedTransaction = .{
            .block_ref = entry.block_ref,
            .tx_ref = entry.tx_ref,
            .transaction_index = entry.transaction_index,
        };

        entry.* = .{};
        self.head = (self.head + 1) % self.entries.len;
        self.count -= 1;

        return completed;
    }

    fn entryAt(self: *FIFOScheduler, offset: usize) *Entry {
        std.debug.assert(offset < self.count);
        return &self.entries[(self.head + offset) % self.entries.len];
    }

    fn headIsReady(self: *const FIFOScheduler) bool {
        return self.count != 0 and
            self.entries[self.head].state == .ready;
    }
};
