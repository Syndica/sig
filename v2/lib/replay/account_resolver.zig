const std = @import("std");
const lib = @import("../lib.zig");

const Unrooted = lib.replay.Unrooted;
const AccountPool = lib.accounts_db.AccountPool;
const AccountLookups = lib.accounts_db.AccountLookups;
const BlockPool = lib.replay.BlockPool;
const BlockRef = lib.replay.BlockRef;
const TransactionPool = lib.replay.TransactionPool;
const VersionedTransaction = lib.solana.transaction.VersionedTransaction;

const TransactionRef = TransactionPool.ItemId;

const account_fetcher = @import("account_fetcher.zig");

const AccountFetcher = account_fetcher.AccountFetcher;

pub const AccountResolver = struct {
    const Self = @This();

    // Arbitrarily chosen for now.
    const MAX_PENDING_TRANSACTIONS = 256;

    /// 2x the max loaded accounts per transaction, to allow for some extra fetches for alt lookups.
    const MAX_FETCH_WORK = 256;

    fetcher: AccountFetcher,
    transaction_pool: *TransactionPool,

    pending_pool: PendingPool,

    /// Used to track the set of transactions with unsubmitted work waiting to be sent to the AccountFetcher.
    active: [MAX_PENDING_TRANSACTIONS]ResolutionId,
    active_len: usize,

    const PendingPool = lib.collections.SharedPool(
        PendingTransaction,
        MAX_PENDING_TRANSACTIONS,
    );

    pub const ResolutionId = PendingPool.ItemId;

    const PendingTransaction = struct {
        block_ref: BlockRef,
        tx_ref: TransactionRef,

        /// The number of valid entries in `work`.
        work_len: u16,

        /// First work item not accepted by AccountFetcher (due to backpressure).
        next_submit: u16,

        /// Used by completion processing.
        // TODO: document this better
        completed: u16,

        work: [MAX_FETCH_WORK]FetchWork,

        //Lowest descriptor index failure observed.
        // lookup_failure: ?LookupFailure,
    };

    const FetchWork = union(enum) {
        /// Index into transaction's static account keys array.
        static: u8,
        /// Byte offset of LUT's pubkey in transaction payload.
        lut: u16,
        // TODO: program, program_data
    };

    const FetchTicket = packed struct(u64) {
        resolution_index: u16,
        work_index: u16,
        _reserved: u32 = 0,
    };

    pub fn init(
        self: *Self,
        allocator: std.mem.Allocator,
        account_pool: *AccountPool,
        account_lookups: *AccountLookups,
        unrooted: *Unrooted,
        block_pool: *BlockPool,
        transaction_pool: *TransactionPool,
    ) void {
        self.* = .{
            .fetcher = undefined,
            .transaction_pool = transaction_pool,
            .pending_pool = undefined,
            .active = undefined,
            .active_len = 0,
        };

        self.fetcher.init(
            allocator,
            account_pool,
            account_lookups,
            unrooted,
            block_pool,
        );

        self.pending_pool.init();
    }

    pub fn resolve(
        self: *Self,
        block_ref: BlockRef,
        tx_id: TransactionPool.ItemId,
    ) error{Full}!ResolutionId {
        const resolution_id = self.pending_pool.createId() catch return error.Full;
        errdefer self.pending_pool.destroyId(resolution_id);

        const transaction = self.transaction_pool.indexToConstPtr(tx_id).view();

        const static_keys = transaction.staticAccountKeys();
        const lookup_count = transaction.layout.address_table_lookup_count;

        const work_len = static_keys.len + lookup_count;
        std.debug.assert(work_len <= MAX_FETCH_WORK);

        const pending = resolution_id.ptr(&self.pending_pool);
        pending.* = .{
            .block_ref = block_ref,
            .tx_ref = tx_id,
            .work_len = @intCast(work_len),
            .next_submit = 0,
            .completed = 0,
            .work = undefined,
        };

        for (0..static_keys.len) |i| {
            pending.work[i] = .{
                .static = @intCast(i),
            };
        }

        var lookups = transaction.addressTableLookups();
        var lookup_index: usize = 0;
        while (lookups.next() catch unreachable) |lookup| {
            pending.work[static_keys.len + lookup_index] = .{
                .lut = lookup.pubkey_byte_offset,
            };
            lookup_index += 1;
        }
        std.debug.assert(lookup_index == lookup_count);

        self.active[self.active_len] = resolution_id;
        self.active_len += 1;

        _ = self.submitWork();

        return resolution_id;
    }

    fn submitWork(self: *Self) bool {
        var made_progress = false;

        for (self.active[0..self.active_len]) |resolution_id| {
            const pending = resolution_id.ptr(&self.pending_pool);
            const transaction = self.transaction_pool.indexToConstPtr(pending.tx_ref).view();

            // Submit as much work as possible to the AccountFetcher, until it returns Full.
            while (pending.next_submit < pending.work_len) {
                const work_index = pending.next_submit;
                const work = pending.work[work_index];

                const pubkey = switch (work) {
                    .static => |i| transaction.staticAccountKeys()[i],
                    .lut => |offset| transaction.pubkeyAtByteOffset(offset).*,
                };

                const ticket = FetchTicket{
                    .resolution_index = @intCast(resolution_id.index()),
                    .work_index = work_index,
                };

                self.fetcher.submit(.{
                    .block_ref = pending.block_ref,
                    .pubkey = pubkey,
                    .user_data = @bitCast(ticket),
                }) catch |err| switch (err) {
                    error.Full => break,
                };

                pending.next_submit += 1;
                made_progress = true;
            }
        }

        return made_progress;
    }

    pub fn pollResolvedTransactions(self: *Self) void {
        _ = self;

        // TODO: drain AccountFetcher completions.
        // TODO: advance transaction resolution state
        // TODO: return resolved transactions to the caller
    }
};
