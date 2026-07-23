const std = @import("std");
const lib = @import("../lib.zig");

const AccountPool = lib.accounts_db.AccountPool;
const AccountLookups = lib.accounts_db.AccountLookups;
const BlockPool = lib.replay.BlockPool;
const BlockRef = lib.replay.BlockRef;

const Unrooted = lib.replay.Unrooted;

const Pubkey = lib.solana.Pubkey;

const AccountRef = AccountPool.AccountRef;

// Arbitrarily chosen for now.
const ENTRY_CAPACITY = 1024;
// Arbitrarily chosen for now.
const WAITER_CAPACITY = 1024;

pub const UserData = u64;

pub const AccountFetcher = struct {
    // TODO: remove this, implement a simple map.
    allocator: std.mem.Allocator,

    account_pool: *AccountPool,
    account_lookups: *AccountLookups,
    unrooted: *Unrooted,
    block_pool: *BlockPool,

    active_fetches: FetchMap,
    entries: [ENTRY_CAPACITY]FetchEntry,
    waiters: [WAITER_CAPACITY]Waiter,

    waiter_pool: WaiterPool,
    entry_pool: EntryPool,

    rooted_head: EntryId.Optional,
    rooted_tail: EntryId.Optional,

    ready_head: EntryId.Optional,
    ready_tail: EntryId.Optional,

    const EntryPool = lib.collections.Pool(FetchEntry, ENTRY_CAPACITY);
    const EntryId = EntryPool.ItemId;

    const WaiterPool = lib.collections.Pool(Waiter, WAITER_CAPACITY);
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

    const RootedTicket = packed struct(u32) {
        entry_index: u16,
        generation: u16,
    };

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
        generation: u16,
        state: State,

        key: FetchKey,

        waiter_head: WaiterId.Optional,
        waiter_tail: WaiterId.Optional,

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

    pub fn submit(
        self: *AccountFetcher,
        request: Request,
    ) error{Full}!void {
        const waiter_id = self.waiter_pool.createId() catch
            return error.Full;

        const waiter = waiter_id.ptr(&self.waiter_pool);
        waiter.* = .{
            .user_data = request.user_data,
            .next = .null,
        };

        errdefer self.waiter_pool.destroyId(waiter_id);

        const key: FetchKey = .{
            .block_ref = request.block_ref,
            .pubkey = request.pubkey,
        };

        // Existing Unrooted lookup, Rooted lookup, or ready result.
        if (self.active_fetches.get(key)) |entry_id| {
            self.appendWaiter(entry_id, waiter_id);
            return;
        }

        const entry_id = self.entry_pool.createId() catch
            return error.Full;
        errdefer self.entry_pool.destroyId(entry_id);

        const entry = entry_id.ptr(&self.entry_pool);
        entry.* = .{
            .key = key,
            .waiter_head = .init(waiter_id),
            .waiter_tail = .init(waiter_id),
            .queue_next = .null,
            .state = undefined,
            .result = undefined,
        };

        self.active_fetches.putAssumeCapacityNoClobber(
            key,
            entry_id,
        );
        errdefer std.debug.assert(
            self.active_fetches.remove(key),
        );

        const unrooted_ref = self.unrooted.fetch(
            &request.pubkey,
            request.block_ref,
            self.block_pool,
            self.account_pool,
        );

        if (unrooted_ref != .invalid) {
            const account = self.account_pool.getAccount(unrooted_ref);

            // An Unrooted tombstone shadows any older Rooted value.
            if (account.lamports == 0) {
                self.releaseAccount(unrooted_ref);
                entry.result = .not_found;
            } else {
                // FetchEntry takes ownership of the reference returned by fetch().
                entry.result = .{ .found = unrooted_ref };
            }

            entry.state = .ready;
            self.enqueueReady(entry_id);
            return;
        }

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

    fn enqueueReady(self: *AccountFetcher, entry_id: EntryId) void {
        const entry = entry_id.ptr(&self.entry_pool);
        std.debug.assert(entry.queue_next == .null);
        std.debug.assert(entry.state == .ready);

        if (self.ready_tail.opt()) |tail_id| {
            tail_id.ptr(&self.entry_pool).queue_next = .init(entry_id);
        } else {
            self.ready_head = .init(entry_id);
        }

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
        const ticket: RootedTicket = @bitCast(response.req_user_data);

        if (ticket.entry_index >= self.entries.len) {
            self.releaseAccount(response.account_index);
            return;
        }

        const entry = &self.entries[ticket.entry_index];

        if (entry.generation != ticket.generation or
            entry.state != .fetching_rooted)
        {
            // Stale response: the slot was reused or is no longer awaiting this read.
            self.releaseAccount(response.account_index);
            return;
        }

        std.debug.assert(response.pubkey.equals(&entry.key.pubkey));

        entry.result = if (response.account_index == .invalid)
            .not_found
        else
            .{ .found = response.account_index };

        entry.state = .ready;
        self.enqueueReady(EntryId.fromInt(ticket.entry_index));
    }

    fn releaseAccount(self: *AccountFetcher, account_ref: AccountRef) void {
        if (account_ref == .invalid) return;
        const account = self.account_pool.getAccount(account_ref);
        if (account.unref()) self.account_pool.free(account_ref);
    }
};
