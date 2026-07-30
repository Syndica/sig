//! Asynchronous account fetch deduplication for Replay.
//!
//! `AccountFetcher` resolves individual account reads against Replay's account view:
//! unrooted fork state first, then rooted AccountsDB storage. Requests for the same
//! `(block_ref, pubkey)` share one fetch entry, and each requester receives a separate
//! completion tagged with its opaque `user_data`.
//!
//! Higher-level transaction resolution is intentionally kept outside this module.
//!
//! The resolver decides which accounts a transaction needs, including lookup-table and
//! program-derived dependencies, while this module only fetches accounts and reports
//! whether each account was found.
const std = @import("std");
const lib = @import("../lib.zig");

const AccountPool = lib.accounts_db.AccountPool;
const AccountLookups = lib.accounts_db.AccountLookups;
const BlockPool = lib.replay.BlockPool;
const BlockRef = lib.replay.BlockRef;

const Unrooted = lib.replay.Unrooted;
const Pubkey = lib.solana.Pubkey;
const AccountRef = AccountPool.AccountRef;

const RootedTestState = lib.accounts_db.RootedTestState;

pub const UserData = u64;
const UserDataType = UserData;

pub const AccountFetcher = AccountFetcherType(Unrooted);

/// Deduplicates and drives asynchronous account reads for Replay.
///
/// The deduplication is implemented by internally maintaining a map keyed by `(block_ref, pubkey)`.
/// When a request is submitted, if an entry already exists for the same key, the request is appended
/// to the existing entry's waiter list.
///
/// The fetcher maintains two queues: one for entries that are queued for rooted lookups and another for
/// entries that are ready with results. The `pollCompletions` method processes these queues,
/// submitting requests to the `AccountLookups` service and draining completed results.
pub fn AccountFetcherType(comptime UnrootedStore: type) type {
    return struct {
        const Self = @This();

        const entry_capacity = 512;
        const waiter_capacity = 512;

        account_pool: *AccountPool,
        account_lookups: *AccountLookups,
        unrooted: *UnrootedStore,
        block_pool: *BlockPool,

        // TODO: remove this, implement a simple map.
        allocator: std.mem.Allocator,
        /// In-flight or ready fetch entries keyed by `(block_ref, pubkey)`.
        active_fetches: FetchMap,

        // NOTE: rational for using separate lists for entries and waiters instead of a single list of
        // union enums is for simplicity mostly, but also since a single FetchEntry can have multiple waiters,
        // we're wasting less space. Though perhaps there's good reason to change this in the future?

        // TODO: flatten both of these by having a pool of nodes.

        /// Backing storage for fetch entries.
        entries: [entry_capacity]FetchEntry,
        /// Backing storage for per-request completion waiters.
        waiters: [waiter_capacity]Waiter,

        /// Pool of waiter slots stored in `waiters`.
        waiter_pool: WaiterPool,
        /// Pool of fetch-entry slots stored in `entries`.
        entry_pool: EntryPool,

        /// Head of entries waiting to be submitted to rooted AccountsDB.
        rooted_head: EntryId.Optional,
        /// Tail of entries waiting to be submitted to rooted AccountsDB.
        rooted_tail: EntryId.Optional,

        /// Head of entries with results ready to deliver to waiters.
        ready_head: EntryId.Optional,
        /// Tail of entries with results ready to deliver to waiters.
        ready_tail: EntryId.Optional,

        const EntryPool = lib.collections.Pool(FetchEntry, u16);
        const EntryId = EntryPool.ItemId;

        const WaiterPool = lib.collections.Pool(Waiter, u16);
        const WaiterId = WaiterPool.ItemId;

        // TODO: custom map.
        // Maps the fetch request (block_ref, pubkey) to the ID of the fetch entry in the `entries` array.
        const FetchMap = std.HashMapUnmanaged(
            FetchKey,
            EntryId,
            std.hash_map.AutoContext(FetchKey),
            80,
        );

        const FetchKey = extern struct {
            block_ref: BlockRef,
            pubkey: Pubkey,
        };

        const Waiter = extern struct {
            user_data: UserDataType,
            next: WaiterId.Optional,
        };

        pub const UserData = UserDataType;

        pub const Request = struct {
            block_ref: BlockRef,
            pubkey: Pubkey,

            // TODO: do we need this? I don;t think the resolver reallt cares about this since pubkey should be enough?
            /// Opaque to AccountFetcher.
            user_data: UserDataType,
        };

        pub const Completion = struct {
            user_data: UserDataType,
            pubkey: Pubkey,
            /// `.invalid` means the account was not found.
            account_ref: AccountRef,
        };

        const FetchEntry = extern struct {
            state: State,

            key: FetchKey,

            waiter_head: WaiterId.Optional,
            waiter_tail: WaiterId.Optional,

            /// links `FetchEntry`s together in the rooted and ready queues.
            /// It's either the next entry waiting to be sent to rooted, or
            /// the entry that has completed and whose result is ready for waiters.
            queue_next: EntryId.Optional,

            result: AccountRef = .invalid,

            const State = enum(u8) {
                free,
                queued_rooted,
                fetching_rooted,
                ready,
            };
        };

        pub fn init(
            self: *Self,
            allocator: std.mem.Allocator,
            account_pool: *AccountPool,
            account_lookups: *AccountLookups,
            unrooted: *UnrootedStore,
            block_pool: *BlockPool,
        ) void {
            var active_fetches: FetchMap = .empty;
            active_fetches.ensureTotalCapacity(
                allocator,
                @intCast(entry_capacity),
            ) catch @panic("failed to allocate active_fetches map");

            self.* = .{
                .allocator = allocator,

                .account_pool = account_pool,
                .account_lookups = account_lookups,
                .unrooted = unrooted,
                .block_pool = block_pool,

                .active_fetches = active_fetches,

                .entries = undefined,
                .waiters = undefined,

                .entry_pool = undefined,
                .waiter_pool = undefined,

                .rooted_head = .null,
                .rooted_tail = .null,

                .ready_head = .null,
                .ready_tail = .null,
            };

            self.entry_pool = .init(self.entries[0..]);
            self.waiter_pool = .init(self.waiters[0..]);
        }

        pub fn deinit(self: *Self) void {
            std.debug.assert(self.active_fetches.count() == 0);

            std.debug.assert(self.rooted_head == .null);
            std.debug.assert(self.rooted_tail == .null);

            std.debug.assert(self.ready_head == .null);
            std.debug.assert(self.ready_tail == .null);

            // Every waiter and entry should have been returned to its pool.
            std.debug.assert(self.entry_pool.free_list.opt() != null);
            std.debug.assert(self.waiter_pool.free_list.opt() != null);

            self.active_fetches.deinit(self.allocator);
            self.* = undefined;
        }

        /// Submits one account fetch request and attaches it to any existing fetch
        /// for the same `(block_ref, pubkey)`.
        ///
        /// New fetches check unrooted state immediately. Misses are queued for rooted
        /// AccountsDB lookup and later driven by `pollCompletions`.
        pub fn submit(self: *Self, request: Request) error{Full}!void {
            // Create a new waiter for this request
            const waiter_id = self.waiter_pool.createId() catch return error.Full;
            errdefer self.waiter_pool.destroyId(waiter_id);

            const waiter = self.waiter_pool.indexToPtr(waiter_id);
            waiter.* = .{
                .user_data = request.user_data,
                .next = .null,
            };

            // Create a key for this request to check if an entry already exists
            // (i.e a fetch is already in progress for this pubkey and block_ref)
            const key: FetchKey = .{
                .block_ref = request.block_ref,
                .pubkey = request.pubkey,
            };

            // Check if there's already a fetch tracked for this key.
            if (self.active_fetches.get(key)) |entry_id| {
                // If there is, append this request's waiter to the existing entry's waiter list.
                // The entry will be completed when the fetch completes, and this request will
                // receive its own completion.
                self.appendWaiter(entry_id, waiter_id);
                return;
            }

            // If there isn't, create a new fetch entry for this key and start the fetch process.
            const entry_id = self.entry_pool.createId() catch return error.Full;
            errdefer self.entry_pool.destroyId(entry_id);

            const entry = self.entry_pool.indexToPtr(entry_id);
            entry.* = .{
                .key = key,
                // There's one one waiter (this request) for the new entry, so both the
                // head and tail point to the same waiter.
                .waiter_head = .init(waiter_id),
                .waiter_tail = .init(waiter_id),
                // This starts as null since its not linked into any queue yet.
                .queue_next = .null,
                // TODO: remove undefineds and add new state.
                .state = undefined,
                .result = .invalid,
            };

            // Track this new fetch entry in the active fetches map.
            self.active_fetches.putAssumeCapacityNoClobber(key, entry_id);
            errdefer std.debug.assert(self.active_fetches.remove(key));

            // Check if the account is already available in the unrooted state.
            // If it is, we can complete the fetch immediately without needing to query the rooted storage.
            const unrooted_ref = self.unrooted.fetch(
                &request.pubkey,
                request.block_ref,
                self.block_pool,
                self.account_pool,
            );

            if (unrooted_ref != .invalid) {
                // FetchEntry takes ownership of the reference returned by fetch().
                entry.result = unrooted_ref;

                // Unrooted had the account, mark ready and return.
                entry.state = .ready;
                self.enqueueReady(entry_id);
                return;
            }

            // If the account isn't available in the unrooted state, we need to query the rooted storage.
            entry.state = .queued_rooted;
            self.enqueueRooted(entry_id);
        }

        /// Drives the fetcher by submitting queued requests to the rooted AccountsDB and draining completed results.
        ///
        /// Returns a slice of completions.
        pub fn pollCompletions(
            self: *Self,
            out: []Completion,
        ) []Completion {
            self.drainRootedResults();
            self.submitRootedRequests();

            var len: usize = 0;
            while (len < out.len) : (len += 1) {
                out[len] = self.popReadyCompletion() orelse break;
            }

            return out[0..len];
        }

        fn popReadyCompletion(self: *Self) ?Completion {
            const entry_id = self.popReady() orelse return null;
            const entry = entry_id.ptr(&self.entry_pool);

            std.debug.assert(entry.state == .ready);

            // Pop the first waiter from the entry's waiter list.
            const waiter_id = entry.waiter_head.opt() orelse unreachable;
            const waiter = waiter_id.ptr(&self.waiter_pool);

            // Move waiter head forward to the next waiter in this entry's list.
            entry.waiter_head = waiter.next;

            // If there are no more waiters, set the tail to null as well.
            if (entry.waiter_head == .null)
                entry.waiter_tail = .null;

            const completion: Completion = .{
                .user_data = waiter.user_data,
                .pubkey = entry.key.pubkey,
                .account_ref = entry.result,
            };

            if (completion.account_ref != .invalid) {
                // The caller receives its own reference.
                self.account_pool
                    .getAccount(completion.account_ref)
                    .ref();
            }

            self.waiter_pool.destroyId(waiter_id);

            // If there are more waiters for this entry, re-enqueue it to the ready queue
            // so the next waiter can receive its completion.
            // TODO: do we want batched-completitions?
            if (entry.waiter_head != .null) {
                // Round-robin completion delivery between ready accounts.
                self.enqueueReady(entry_id);
            } else {
                // No more waiters for this entry, retire it and free its resources.
                self.retireEntry(entry_id);
            }

            return completion;
        }

        fn enqueueRooted(self: *Self, entry_id: EntryId) void {
            const entry = entry_id.ptr(&self.entry_pool);
            std.debug.assert(entry.queue_next == .null);

            if (self.rooted_tail.opt()) |tail_id| {
                tail_id.ptr(&self.entry_pool).queue_next = .init(entry_id);
            } else {
                self.rooted_head = .init(entry_id);
            }

            self.rooted_tail = .init(entry_id);
        }

        /// Dequeue the next entry from the rooted queue.
        fn popRooted(self: *Self) ?EntryId {
            const entry_id = self.rooted_head.opt() orelse return null;
            const entry = entry_id.ptr(&self.entry_pool);

            self.rooted_head = entry.queue_next;
            if (self.rooted_head == .null)
                self.rooted_tail = .null;

            entry.queue_next = .null;
            return entry_id;
        }

        /// Enqueue a ready entry to the ready queue, which is used to deliver completions to waiters.
        fn enqueueReady(self: *Self, entry_id: EntryId) void {
            const entry = self.entry_pool.indexToPtr(entry_id);
            std.debug.assert(entry.queue_next == .null);
            std.debug.assert(entry.state == .ready);

            // Add the entry to the end of the ready queue.
            if (self.ready_tail.opt()) |tail_id| {
                // update current tail's next pointer to the new entry.
                tail_id.ptr(&self.entry_pool).queue_next = .init(entry_id);
            } else {
                // Empty queue, so set the head to the new entry.
                self.ready_head = .init(entry_id);
            }

            // Update the tail to the new entry.
            self.ready_tail = .init(entry_id);
        }

        /// Dequeue the next entry from the ready queue.
        fn popReady(self: *Self) ?EntryId {
            const entry_id = self.ready_head.opt() orelse return null;
            const entry = entry_id.ptr(&self.entry_pool);

            // update the head to the next entry in the queue.
            self.ready_head = entry.queue_next;
            if (self.ready_head == .null)
                self.ready_tail = .null;

            entry.queue_next = .null;
            return entry_id;
        }

        fn appendWaiter(self: *Self, entry_id: EntryId, waiter_id: WaiterId) void {
            const entry = entry_id.ptr(&self.entry_pool);
            const waiter = waiter_id.ptr(&self.waiter_pool);

            std.debug.assert(waiter.next == .null);

            if (entry.waiter_tail.opt()) |tail_id| {
                tail_id.ptr(&self.waiter_pool).next = .init(waiter_id);
            } else {
                entry.waiter_head = .init(waiter_id);
            }

            entry.waiter_tail = .init(waiter_id);
        }

        fn retireEntry(self: *Self, entry_id: EntryId) void {
            const entry = entry_id.ptr(&self.entry_pool);

            std.debug.assert(entry.state == .ready);
            std.debug.assert(entry.waiter_head == .null);
            std.debug.assert(entry.waiter_tail == .null);

            std.debug.assert(self.active_fetches.remove(entry.key));

            self.releaseAccount(entry.result);

            self.entry_pool.destroyId(entry_id);
        }

        /// Empty rooted queue of requests by submitting them to rooted.
        fn submitRootedRequests(self: *Self) void {
            var writer = self.account_lookups.in.get(.writer);
            var submitted: usize = 0;

            while (self.rooted_head != .null) {
                const request_out = writer.next() orelse break;

                // NOTE: safe to unwrap since checked in loop condition.
                const entry_id = self.popRooted().?;
                const entry = entry_id.ptr(&self.entry_pool);

                std.debug.assert(entry.state == .queued_rooted);

                request_out.* = .{
                    .req_user_data = @intCast(entry_id.index()),
                    .pubkey = entry.key.pubkey,
                };

                entry.state = .fetching_rooted;
                submitted += 1;
            }

            writer.markUsed();
        }

        /// Drains results from the rooted DB.
        ///
        /// For each account drained, the corresponding fetch entry is
        /// updated with the result and moved to the ready queue.
        ///
        /// Returns true if any results were processed, false if the queue was empty.
        fn drainRootedResults(self: *Self) void {
            var reader = self.account_lookups.out.get(.reader);
            var consumed: usize = 0;

            while (reader.next()) |response| {
                consumed += 1;
                self.processRootedResult(response.*);
            }

            reader.markUsed();
        }

        /// Processes a single result from the rooted DB, updating the corresponding fetch entry
        /// and moving it to the ready queue.
        fn processRootedResult(
            self: *Self,
            response: AccountLookups.Result,
        ) void {
            const entry_index = response.req_user_data;

            // Totally unexpected if the entry index is out of bounds, this should never happen.
            // TODO: make this a panic?
            if (entry_index >= self.entry_pool.len) {
                self.releaseAccount(response.account_index);
                return;
            }

            const entry_id = EntryId.fromInt(@intCast(entry_index));
            const entry = entry_id.ptr(&self.entry_pool);

            // We don't expect to receive a result for an entry that isn't in the fetching state.
            // TODO: make this a panic?
            if (entry.state != .fetching_rooted) {
                self.releaseAccount(response.account_index);
                return;
            }

            std.debug.assert(response.pubkey.equals(&entry.key.pubkey));

            // Mark the entry as ready and store the result.
            entry.result = response.account_index;
            entry.state = .ready;

            // Move the entry into the ready queue.
            self.enqueueReady(entry_id);
        }

        /// Release an account reference back to the account pool, if it's valid.
        fn releaseAccount(self: *Self, account_ref: AccountRef) void {
            if (account_ref == .invalid) return;
            const account = self.account_pool.getAccount(account_ref);
            if (account.unref()) self.account_pool.free(account_ref);
        }
    };
}

// Smaller for unit tests.
const TestUnrooted = lib.replay.UnrootedType(.{
    .max_blocks = 4,
    .max_mutations_per_block = 8,
});

const TestFetcher = AccountFetcherType(TestUnrooted);

const FetcherTestState = struct {
    account_lookups: AccountLookups,

    block_pool_memory: [BlockPool.size()]u8 align(@alignOf(BlockPool)),
    block_pool: *BlockPool,

    unrooted: TestUnrooted,
    fetcher: TestFetcher,

    fn init(
        self: *FetcherTestState,
        account_pool: *AccountPool,
    ) void {
        self.account_lookups.init();

        self.block_pool = @ptrCast(&self.block_pool_memory);
        self.block_pool.init();

        self.unrooted.init();

        self.fetcher.init(
            std.testing.allocator,
            account_pool,
            &self.account_lookups,
            &self.unrooted,
            self.block_pool,
        );
    }

    fn deinit(self: *FetcherTestState) void {
        self.fetcher.deinit();
    }

    fn addBlock(
        self: *FetcherTestState,
        parent: ?BlockRef,
        slot: u64,
    ) !BlockRef {
        const block_ref = try self.block_pool.createId();
        block_ref.ptr(self.block_pool).* = .{
            .parent = .init(parent),
            .slot = .init(slot),
        };
        return block_ref;
    }

    fn respond(
        self: *FetcherTestState,
        request: AccountLookups.Request,
        account_ref: AccountRef,
    ) !void {
        var writer = self.account_lookups.out.get(.writer);
        const response = writer.next() orelse
            return error.ResponseRingFull;

        response.* = .{
            .req_user_data = request.req_user_data,
            .pubkey = request.pubkey,
            .account_index = account_ref,
        };
        writer.markUsed();
    }
};

test "rooted miss completes as not found" {
    var account_pool: AccountPool = undefined;
    account_pool.init(0);

    var account_lookups: AccountLookups = undefined;
    account_lookups.init();

    var block_pool_memory: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const block_pool: *BlockPool = @ptrCast(&block_pool_memory);
    block_pool.init();

    const block_ref = try block_pool.createId();
    block_ref.ptr(block_pool).* = .{
        .slot = .init(1),
    };

    var unrooted: TestUnrooted = undefined;
    unrooted.init();

    var fetcher: TestFetcher = undefined;
    fetcher.init(
        std.testing.allocator,
        &account_pool,
        &account_lookups,
        &unrooted,
        block_pool,
    );
    defer fetcher.deinit();

    const pubkey: Pubkey = .parse("AUCuaE1ZfgKAReZedngX55iW1NaCjFcDQ1pRvP4caix8");

    try fetcher.submit(.{
        .block_ref = block_ref,
        .pubkey = pubkey,
        .user_data = 42,
    });

    // Publish the queued Rooted request.
    var completions_buf: [1]TestFetcher.Completion = undefined;
    const completions = fetcher.pollCompletions(&completions_buf);
    try std.testing.expectEqual(0, completions.len);

    var request_reader = account_lookups.in.get(.reader);
    const rooted_request = (request_reader.next() orelse
        return error.MissingRootedRequest).*;
    request_reader.markUsed();

    try std.testing.expect(rooted_request.pubkey.equals(&pubkey));

    // Simulate AccountsDB returning not-found.
    var response_writer = account_lookups.out.get(.writer);
    const response = response_writer.next() orelse
        return error.ResponseRingFull;

    response.* = .{
        .req_user_data = rooted_request.req_user_data,
        .pubkey = rooted_request.pubkey,
        .account_index = .invalid,
    };
    response_writer.markUsed();

    const rooted_completions = fetcher.pollCompletions(&completions_buf);
    try std.testing.expectEqual(1, rooted_completions.len);

    const completion = rooted_completions[0];

    try std.testing.expectEqual(42, completion.user_data);
    try std.testing.expect(completion.pubkey.equals(&pubkey));
    try std.testing.expectEqual(AccountRef.invalid, completion.account_ref);
    try std.testing.expectEqual(0, fetcher.pollCompletions(&completions_buf).len);
}

test "duplicate requests share rooted fetch and receive owned references" {
    const logger = lib.telemetry.Logger("Rooted.test").noop;

    var rooted_state = try RootedTestState.init(logger);
    defer rooted_state.deinit();

    const expected: RootedTestState.Account = .{
        .pubkey = Pubkey.parse("F4GpAFr6vrxU3Y887F3XWkXRgybCVjZNk63m72f6pump"),
        .owner = Pubkey.parse("11111111111111111111111111111111"),
        .lamports = 42,
        .rent_epoch = 3,
        .executable = false,
        .data = "rooted account data",
    };

    try rooted_state.putAccounts(logger, &.{expected});

    var state: FetcherTestState = undefined;
    state.init(rooted_state.account_pool);
    defer state.deinit();

    const block_ref = try state.addBlock(null, 2);

    try state.fetcher.submit(.{
        .block_ref = block_ref,
        .pubkey = expected.pubkey,
        .user_data = 10,
    });
    try state.fetcher.submit(.{
        .block_ref = block_ref,
        .pubkey = expected.pubkey,
        .user_data = 20,
    });

    // Both submissions share one fetch entry and one queued Rooted request.
    try std.testing.expectEqual(1, state.fetcher.active_fetches.count());

    const entry_id = state.fetcher.rooted_head.opt() orelse
        return error.MissingRootedFetchEntry;
    try std.testing.expectEqual(entry_id, state.fetcher.rooted_tail.opt().?);

    const entry = entry_id.ptr(&state.fetcher.entry_pool);
    try std.testing.expectEqual(.queued_rooted, entry.state);

    const first_waiter_id = entry.waiter_head.opt() orelse
        return error.MissingFirstWaiter;
    const second_waiter_id = first_waiter_id.ptr(&state.fetcher.waiter_pool).next.opt() orelse
        return error.MissingSecondWaiter;
    try std.testing.expectEqual(second_waiter_id, entry.waiter_tail.opt().?);
    try std.testing.expectEqual(.null, second_waiter_id.ptr(&state.fetcher.waiter_pool).next);

    var completions_buf: [2]TestFetcher.Completion = undefined;
    const published_completions = state.fetcher.pollCompletions(&completions_buf);
    try std.testing.expectEqual(0, published_completions.len);

    var request_reader = state.account_lookups.in.get(.reader);
    const request = request_reader.next() orelse
        return error.MissingRootedRequest;

    try std.testing.expect(request.pubkey.equals(&expected.pubkey));
    try std.testing.expect(request_reader.next() == null);

    try std.testing.expect(try rooted_state.rooted.queueRead(
        .from(logger),
        request,
    ));
    request_reader.markUsed();

    const rooted_result = while (true) {
        break try rooted_state.rooted.pollRead(.from(logger)) orelse
            continue;
    };

    var response_writer = state.account_lookups.out.get(.writer);
    response_writer.next().?.* = rooted_result;
    response_writer.markUsed();

    const completions = state.fetcher.pollCompletions(&completions_buf);
    try std.testing.expectEqual(2, completions.len);

    const first = completions[0];
    const second = completions[1];

    try std.testing.expectEqual(10, first.user_data);
    try std.testing.expectEqual(20, second.user_data);
    try std.testing.expectEqual(first.account_ref, second.account_ref);
    try std.testing.expect(first.account_ref != .invalid);

    const account =
        rooted_state.account_pool.getAccount(first.account_ref);

    try std.testing.expect(account.pubkey.equals(&expected.pubkey));
    try std.testing.expectEqual(expected.lamports, account.lamports);
    try std.testing.expectEqualStrings(expected.data, account.getData());

    // FetchEntry has retired; both completion callers own one ref.
    try std.testing.expectEqual(
        2,
        account.ref_count.load(.monotonic),
    );

    try std.testing.expect(!account.unref());
    try std.testing.expect(account.unref());
    rooted_state.account_pool.free(first.account_ref);
}

test "unrooted accounts bypass rooted and zero-lamport accounts return refs" {
    const memory_len = 64 * 1024;
    const memory = try std.testing.allocator.alignedAlloc(
        u8,
        .of(AccountPool),
        @sizeOf(AccountPool) + memory_len,
    );
    defer std.testing.allocator.free(memory);

    const account_pool: *AccountPool = @ptrCast(memory.ptr);
    account_pool.init(memory_len);

    var state: FetcherTestState = undefined;
    state.init(account_pool);
    defer state.deinit();

    const block_ref = try state.addBlock(null, 1);

    const found_pk = Pubkey.parse("9oDndFiC7RW42vZcmSzacTKMWE9kgeqnzwXDGLSkpump");
    const tombstone_pk = Pubkey.parse("USD1ttGY1N17NEEHLmELoaybftRBUSErhqYiQzvEmuB");

    const found_ref = try account_pool.alloc(0);
    account_pool.getAccount(found_ref).* = .{
        .ref_count = .init(1),
        .pubkey = found_pk,
        .owner = .ZEROES,
        .lamports = 100,
        .rent_epoch = 0,
        .data = .{
            .executable = false,
            .len = 0,
        },
    };

    const tombstone_ref = try account_pool.alloc(0);
    account_pool.getAccount(tombstone_ref).* = .{
        .ref_count = .init(1),
        .pubkey = tombstone_pk,
        .owner = .ZEROES,
        .lamports = 0,
        .rent_epoch = 0,
        .data = .{
            .executable = false,
            .len = 0,
        },
    };

    try std.testing.expectEqual(
        AccountRef.invalid,
        state.unrooted.put(block_ref, account_pool, found_ref),
    );
    try std.testing.expectEqual(
        AccountRef.invalid,
        state.unrooted.put(block_ref, account_pool, tombstone_ref),
    );

    // Drop the original owners; Unrooted now owns one reference each.
    try std.testing.expect(!account_pool.getAccount(found_ref).unref());
    try std.testing.expect(!account_pool.getAccount(tombstone_ref).unref());

    try state.fetcher.submit(.{
        .block_ref = block_ref,
        .pubkey = found_pk,
        .user_data = 1,
    });
    try state.fetcher.submit(.{
        .block_ref = block_ref,
        .pubkey = tombstone_pk,
        .user_data = 2,
    });

    // Neither request should reach Rooted.
    var rooted_reader = state.account_lookups.in.get(.reader);
    try std.testing.expect(rooted_reader.next() == null);

    var completions_buf: [2]TestFetcher.Completion = undefined;
    const completions = state.fetcher.pollCompletions(&completions_buf);
    try std.testing.expectEqual(2, completions.len);

    const found = completions[0];
    const tombstone = completions[1];

    try std.testing.expectEqual(found_ref, found.account_ref);
    try std.testing.expectEqual(tombstone_ref, tombstone.account_ref);

    // Release completion ownership.
    try std.testing.expect(
        !account_pool.getAccount(found.account_ref).unref(),
    );
    try std.testing.expect(
        !account_pool.getAccount(tombstone.account_ref).unref(),
    );

    // Release the references owned by Unrooted before ending the test.
    try std.testing.expect(account_pool.getAccount(found_ref).unref());
    account_pool.free(found_ref);

    try std.testing.expect(account_pool.getAccount(tombstone_ref).unref());
    account_pool.free(tombstone_ref);
}

test "rooted responses complete by request id out of order" {
    var account_pool: AccountPool = undefined;
    account_pool.init(0);

    var state: FetcherTestState = undefined;
    state.init(&account_pool);
    defer state.deinit();

    const block_ref = try state.addBlock(null, 1);
    const first_pk = Pubkey.parse("SysvarC1ock11111111111111111111111111111111");
    const second_pk = Pubkey.parse("SysvarRent111111111111111111111111111111111");

    try state.fetcher.submit(.{
        .block_ref = block_ref,
        .pubkey = first_pk,
        .user_data = 11,
    });
    try state.fetcher.submit(.{
        .block_ref = block_ref,
        .pubkey = second_pk,
        .user_data = 22,
    });

    var completions_buf: [2]TestFetcher.Completion = undefined;
    const published_completions = state.fetcher.pollCompletions(&completions_buf);
    try std.testing.expectEqual(0, published_completions.len);

    var reader = state.account_lookups.in.get(.reader);
    const first_request = reader.next().?.*;
    const second_request = reader.next().?.*;
    reader.markUsed();

    // Return the second lookup first.
    try state.respond(second_request, .invalid);
    try state.respond(first_request, .invalid);

    const completions = state.fetcher.pollCompletions(&completions_buf);
    try std.testing.expectEqual(2, completions.len);

    const first_completion = completions[0];
    const second_completion = completions[1];

    try std.testing.expectEqual(
        22,
        first_completion.user_data,
    );
    try std.testing.expect(
        first_completion.pubkey.equals(&second_pk),
    );

    try std.testing.expectEqual(
        11,
        second_completion.user_data,
    );
    try std.testing.expect(
        second_completion.pubkey.equals(&first_pk),
    );
}

test "rooted request remains queued while lookup ring is full" {
    var account_pool: AccountPool = undefined;
    account_pool.init(0);

    var state: FetcherTestState = undefined;
    state.init(&account_pool);
    defer state.deinit();

    // Occupy the entire Rooted request ring.
    var filler = state.account_lookups.in.get(.writer);
    for (0..AccountLookups.capacity) |i| {
        filler.next().?.* = .{
            .req_user_data = @intCast(i),
            .pubkey = .ZEROES,
        };
    }
    filler.markUsed();

    const block_ref = try state.addBlock(null, 1);
    const pubkey = Pubkey.parse("SysvarC1ock11111111111111111111111111111111");

    try state.fetcher.submit(.{
        .block_ref = block_ref,
        .pubkey = pubkey,
        .user_data = 77,
    });

    // The entry remains on rooted_head because no ring slot is available.
    var completions_buf: [1]TestFetcher.Completion = undefined;
    try std.testing.expectEqual(
        0,
        state.fetcher.pollCompletions(&completions_buf).len,
    );
    try std.testing.expect(state.fetcher.rooted_head != .null);
    try std.testing.expectEqual(
        0,
        state.fetcher.pollCompletions(&completions_buf).len,
    );

    // Drain the filler requests.
    var reader = state.account_lookups.in.get(.reader);
    for (0..AccountLookups.capacity) |_| {
        _ = reader.next() orelse return error.MissingFillerRequest;
    }
    reader.markUsed();

    // The next poll can now publish the real request.
    try std.testing.expectEqual(
        0,
        state.fetcher.pollCompletions(&completions_buf).len,
    );

    var actual_reader = state.account_lookups.in.get(.reader);
    const request = actual_reader.next().?.*;
    actual_reader.markUsed();

    try std.testing.expect(request.pubkey.equals(&pubkey));

    try state.respond(request, .invalid);
    const completions = state.fetcher.pollCompletions(&completions_buf);
    try std.testing.expectEqual(1, completions.len);

    const completion = completions[0];
    try std.testing.expectEqual(
        77,
        completion.user_data,
    );
    try std.testing.expectEqual(
        AccountRef.invalid,
        completion.account_ref,
    );
}
