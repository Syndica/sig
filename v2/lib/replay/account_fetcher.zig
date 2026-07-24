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

/// Deduplicates and drives asynchronous account reads for Replay.
///
/// The deduplication is implemented by internally maintaining a map keyed by `(block_ref, pubkey)`.
/// When a request is submitted, if an entry already exists for the same key, the request is appended
/// to the existing entry's waiter list.
///
/// The fetcher maintains two queues: one for entries that are queued for rooted lookups and another for
/// entries that are ready with results. The `poll` method processes these queues, submitting
/// requests to the `AccountLookups` service and draining completed results.
pub const AccountFetcher = struct {
    account_pool: *AccountPool,
    account_lookups: *AccountLookups,
    unrooted: *Unrooted,
    block_pool: *BlockPool,

    // TODO: remove this, implement a simple map.
    allocator: std.mem.Allocator,
    /// In-flight or ready fetch entries keyed by `(block_ref, pubkey)`.
    active_fetches: FetchMap,

    // NOTE: rational for using separate lists for entries and waiters instead of a single list of
    // union enums is for simplicity mostly, but also since a single FetchEntry can have multiple waiters,
    // we're wasting less space. Though perhaps there's good reason to change this in the future?

    /// Backing storage for fetch entries.
    entries: [512]FetchEntry,
    /// Backing storage for per-request completion waiters.
    waiters: [512]Waiter,

    waiter_pool: WaiterPool,
    entry_pool: EntryPool,

    rooted_head: EntryId.Optional,
    rooted_tail: EntryId.Optional,

    ready_head: EntryId.Optional,
    ready_tail: EntryId.Optional,

    const EntryPool = lib.collections.Pool(FetchEntry, u16);
    const EntryId = EntryPool.ItemId;

    const WaiterPool = lib.collections.Pool(Waiter, u16);
    const WaiterId = WaiterPool.ItemId;

    // TODO: custom map.
    const FetchMap = std.HashMapUnmanaged(
        FetchKey,
        EntryId,
        .{},
        80,
    );

    const FetchKey = struct {
        block_ref: BlockRef,
        pubkey: Pubkey,
    };

    const Waiter = struct {
        user_data: UserData,
        next: WaiterId.Optional,
    };

    pub const UserData = u64;

    pub const Request = struct {
        block_ref: BlockRef,
        pubkey: Pubkey,

        /// Opaque to AccountFetcher.
        user_data: UserData,
    };

    pub const Completion = struct {
        user_data: UserData,
        pubkey: Pubkey,
        result: Result,
    };

    pub const Result = union(enum) {
        found: AccountPool.AccountRef,
        not_found,
    };

    const FetchEntry = struct {
        state: State,

        key: FetchKey,

        waiter_head: WaiterId.Optional,
        waiter_tail: WaiterId.Optional,

        /// links `FetchEntry`s together in the rooted and ready queues.
        /// It's either the next entry waiting to be sent to rooted, or
        /// an entry that has completed and whose result is ready for waiters.
        queue_next: EntryId.Optional,

        result: Result = undefined,

        const State = enum {
            free,
            queued_rooted,
            fetching_rooted,
            ready,
        };
    };

    pub fn init(
        allocator: std.mem.Allocator,
        account_pool: *AccountPool,
        account_lookups: *AccountLookups,
        unrooted: *Unrooted,
        block_pool: *BlockPool,
        entry_buf: []FetchEntry,
        waiter_buf: []Waiter,
    ) !AccountFetcher {
        var active_fetches: FetchMap = .empty;
        try active_fetches.ensureTotalCapacity(
            allocator,
            @intCast(entry_buf.len),
        );

        return .{
            .allocator = allocator,

            .account_pool = account_pool,
            .account_lookups = account_lookups,
            .unrooted = unrooted,
            .block_pool = block_pool,

            .active_fetches = active_fetches,

            .entry_pool = .init(entry_buf),
            .waiter_pool = .init(waiter_buf),

            .rooted_head = .null,
            .rooted_tail = .null,

            .ready_head = .null,
            .ready_tail = .null,
        };
    }

    pub fn deinit(self: *AccountFetcher) void {
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
    /// AccountsDB lookup and later driven by `poll`.
    pub fn submit(self: *AccountFetcher, request: Request) error{Full}!void {
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
            .result = undefined,
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
            const account = self.account_pool.getAccount(unrooted_ref);

            // An Unrooted tombstone shadows any older Rooted value (deleted account).
            if (account.lamports == 0) {
                self.releaseAccount(unrooted_ref);
                entry.result = .not_found;
            } else {
                // FetchEntry takes ownership of the reference returned by fetch().
                entry.result = .{ .found = unrooted_ref };
            }

            // Unrooted had the account, mark ready and return.
            entry.state = .ready;
            self.enqueueReady(entry_id);
            return;
        }

        // If the account isn't available in the unrooted state, we need to query the rooted storage.
        entry.state = .queued_rooted;
        self.enqueueRooted(entry_id);
    }

    pub fn poll(self: *AccountFetcher) bool {
        var progressed: u1 = 0;
        progressed |= self.drainRootedResults();
        progressed |= self.submitRootedRequests();
        return progressed;
    }

    pub fn popCompletion(self: *AccountFetcher) ?Completion {
        const entry_id = self.popReady() orelse return null;
        const entry = entry_id.ptr(&self.entry_pool);

        std.debug.assert(entry.state == .ready);

        const waiter_id = entry.waiter_head.opt() orelse
            unreachable;
        const waiter = waiter_id.ptr(&self.waiter_pool);

        entry.waiter_head = waiter.next;
        if (entry.waiter_head == .null)
            entry.waiter_tail = .null;

        const completion: Completion = .{
            .user_data = waiter.user_data,
            .pubkey = entry.key.pubkey,
            .result = switch (entry.result) {
                .not_found => .not_found,
                .found => |account_ref| result: {
                    // The caller receives its own reference.
                    self.account_pool
                        .getAccount(account_ref)
                        .ref();

                    break :result .{ .found = account_ref };
                },
            },
        };

        self.waiter_pool.destroyId(waiter_id);

        if (entry.waiter_head != .null) {
            // Round-robin completion delivery between ready accounts.
            self.enqueueReady(entry_id);
        } else {
            self.retireEntry(entry_id);
        }

        return completion;
    }

    fn enqueueRooted(self: *AccountFetcher, entry_id: EntryId) void {
        const entry = entry_id.ptr(&self.entry_pool);
        std.debug.assert(entry.queue_next == .null);

        if (self.rooted_tail.opt()) |tail_id| {
            tail_id.ptr(&self.entry_pool).queue_next = .init(entry_id);
        } else {
            self.rooted_head = .init(entry_id);
        }

        self.rooted_tail = .init(entry_id);
    }

    fn popRooted(self: *AccountFetcher) ?EntryId {
        const entry_id = self.rooted_head.opt() orelse return null;
        const entry = entry_id.ptr(&self.entry_pool);

        self.rooted_head = entry.queue_next;
        if (self.rooted_head == .null)
            self.rooted_tail = .null;

        entry.queue_next = .null;
        return entry_id;
    }

    /// Enqueue a ready entry to the ready queue, which is used to deliver completions to waiters.
    fn enqueueReady(self: *AccountFetcher, entry_id: EntryId) void {
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

    fn popReady(self: *AccountFetcher) ?EntryId {
        const entry_id = self.ready_head.opt() orelse return null;
        const entry = entry_id.ptr(&self.entry_pool);

        self.ready_head = entry.queue_next;
        if (self.ready_head == .null)
            self.ready_tail = .null;

        entry.queue_next = .null;
        return entry_id;
    }

    fn appendWaiter(self: *AccountFetcher, entry_id: EntryId, waiter_id: WaiterId) void {
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

    fn retireEntry(self: *AccountFetcher, entry_id: EntryId) void {
        const entry = entry_id.ptr(&self.entry_pool);

        std.debug.assert(entry.state == .ready);
        std.debug.assert(entry.waiter_head == .null);
        std.debug.assert(entry.waiter_tail == .null);

        std.debug.assert(self.active_fetches.remove(entry.key));

        switch (entry.result) {
            .not_found => {},
            .found => |account_ref| {
                self.releaseAccount(account_ref);
            },
        }

        self.entry_pool.destroyId(entry_id);
    }

    fn submitRootedRequests(self: *AccountFetcher) bool {
        var writer = self.account_lookups.in.get(.writer);
        var submitted: usize = 0;

        while (self.rooted_head != .null) {
            const request_out = writer.next() orelse break;

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

        if (submitted == 0)
            return false;

        writer.markUsed();
        return true;
    }

    fn drainRootedResults(self: *AccountFetcher) bool {
        var reader = self.account_lookups.out.get(.reader);
        var consumed: usize = 0;

        while (reader.next()) |response| {
            consumed += 1;
            self.processRootedResult(response.*);
        }

        if (consumed == 0)
            return false;

        reader.markUsed();
        return true;
    }

    fn processRootedResult(
        self: *AccountFetcher,
        response: AccountLookups.Result,
    ) void {
        const entry_index = response.req_user_data;

        if (entry_index >= self.entry_pool.len) {
            self.releaseAccount(response.account_index);
            return;
        }

        const entry_id = EntryId.fromInt(@intCast(entry_index));
        const entry = entry_id.ptr(&self.entry_pool);

        if (entry.state != .fetching_rooted) {
            self.releaseAccount(response.account_index);
            return;
        }

        std.debug.assert(response.pubkey.equals(&entry.key.pubkey));

        entry.result = if (response.account_index == .invalid)
            .not_found
        else
            .{ .found = response.account_index };

        entry.state = .ready;
        self.enqueueReady(entry_id);
    }

    /// Release an account reference back to the account pool, if it's valid.
    fn releaseAccount(self: *AccountFetcher, account_ref: AccountRef) void {
        if (account_ref == .invalid) return;
        const account = self.account_pool.getAccount(account_ref);
        if (account.unref()) self.account_pool.free(account_ref);
    }
};
