const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;
const vote_program = sig.runtime.program.vote;
const stake_program = sig.runtime.program.stake;
const stake_accounts = sig.core.stake_accounts;
const vote_accounts = sig.core.vote_accounts;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const VoteAccounts = sig.core.vote_accounts.VoteAccounts;
const VoteAccount = sig.core.vote_accounts.VoteAccount;
const StakeAccount = sig.core.stake_accounts.StakeAccount;
const StakeAccounts = sig.core.stake_accounts.StakeAccounts;

const AccountSharedData = sig.runtime.AccountSharedData;
const VoteState = sig.runtime.program.vote.state.VoteState;
const VoteStateVersions = sig.runtime.program.vote.state.VoteStateVersions;
const Rent = sig.runtime.sysvar.Rent;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const StakeHistoryEntry = sig.runtime.sysvar.StakeHistory.Entry;
const ClusterStake = sig.runtime.sysvar.StakeHistory.ClusterStake;

const RwMux = sig.sync.RwMux;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub const StakesCache = struct {
    stakes: RwMux(Stakes),

    pub fn initEmpty(allocator: std.mem.Allocator, epoch: Epoch) Allocator.Error!StakesCache {
        return .{ .stakes = RwMux(Stakes).init(try Stakes.initEmpty(allocator, epoch)) };
    }

    pub fn deinit(self: *StakesCache, allocator: Allocator) void {
        var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
        defer stakes_guard.unlock();
        stakes.deinit(allocator);
    }

    pub fn checkAndStore(
        self: *StakesCache,
        allocator: Allocator,
        pubkey: Pubkey,
        account: AccountSharedData,
        new_rate_activation_epoch: ?Epoch,
    ) Allocator.Error!void {
        if (account.lamports == 0) {
            if (vote_program.ID.equals(&account.owner)) {
                var stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                stakes.removeVoteAccount(allocator, pubkey);
            } else if (stake_program.ID.equals(&account.owner)) {
                var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                stakes.removeStakeAccount(allocator, pubkey, new_rate_activation_epoch);
            }
            return;
        }

        if (vote_program.ID.equals(&account.owner)) {
            if (VoteStateVersions.isCorrectSizeAndInitialized(account.data)) {
                const vote_account = VoteAccount.fromAccountSharedData(
                    allocator,
                    try account.clone(allocator),
                ) catch {
                    var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    stakes.removeVoteAccount(allocator, pubkey);
                    return;
                };
                var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try stakes.upsertVoteAccount(allocator, pubkey, vote_account, new_rate_activation_epoch);
            } else {
                var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                stakes.removeVoteAccount(allocator, pubkey);
            }
        } else if (stake_program.ID.equals(&account.owner)) {
            const stake_account = StakeAccount.fromAccountSharedData(
                allocator,
                try account.clone(allocator),
            ) catch {
                var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                stakes.removeStakeAccount(allocator, pubkey, new_rate_activation_epoch);
                return;
            };
            var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try stakes.upsertStakeAccount(
                allocator,
                pubkey,
                stake_account,
                new_rate_activation_epoch,
            );
        }
    }
};

pub const Stakes = struct {
    epoch: Epoch,
    vote_accounts: VoteAccounts,
    stake_accounts: StakeAccounts,
    stake_history: StakeHistory,
    // unused: u64,

    pub fn initEmpty(allocator: Allocator, epoch: Epoch) Allocator.Error!Stakes {
        return .{
            .epoch = epoch,
            .vote_accounts = .{},
            .stake_accounts = .{},
            .stake_history = try .default(allocator),
            // .unused = 0,
        };
    }

    pub fn deinit(self: *const Stakes, allocator: Allocator) void {
        var vote_accs = self.vote_accounts;
        vote_accs.deinit(allocator);
        var stake_accs = self.stake_accounts;
        for (stake_accs.values()) |*stake_account| stake_account.deinit(allocator);
        stake_accs.deinit(allocator);
        self.stake_history.deinit(allocator);
    }

    pub fn calculateStake(
        self: *Stakes,
        pubkey: Pubkey,
        new_rate_activation_epoch: ?Epoch,
    ) u64 {
        var stake: u64 = 0;
        for (self.stake_accounts.values()) |*stake_account| {
            const delegation = stake_account.getDelegation();
            if (!delegation.voter_pubkey.equals(&pubkey)) continue;
            stake += delegation.getStake(
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
            );
        }
        return stake;
    }

    /// Takes ownership of `account`.
    pub fn upsertVoteAccount(
        self: *Stakes,
        allocator: Allocator,
        pubkey: Pubkey,
        account: VoteAccount,
        new_rate_activation_epoch: ?Epoch,
    ) Allocator.Error!void {
        std.debug.assert(account.account.lamports > 0);
        errdefer account.deinit(allocator);

        // TODO: move this function call into vote accounts insert to prevent execution
        // on failure paths in vote_accounts.insert
        const stake = self.calculateStake(pubkey, new_rate_activation_epoch);

        const maybe_old_account = try self.vote_accounts.insert(allocator, pubkey, account, stake);

        if (maybe_old_account) |old_account| old_account.deinit(allocator);
    }

    /// Takes ownership of `account`.
    pub fn upsertStakeAccount(
        self: *Stakes,
        allocator: Allocator,
        pubkey: Pubkey,
        account: StakeAccount,
        new_rate_activation_epoch: ?Epoch,
    ) Allocator.Error!void {
        std.debug.assert(account.account.lamports > 0);
        errdefer account.deinit(allocator);

        const delegation = account.getDelegation();
        const voter_pubkey = delegation.voter_pubkey;
        const stake = delegation.getStake(
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
        );

        if (try self.stake_accounts.fetchPut(
            allocator,
            pubkey,
            account,
        )) |old_account_entry| {
            const old_account = old_account_entry.value;
            defer old_account.deinit(allocator);

            const old_delegation = old_account.getDelegation();
            const old_voter_pubkey = old_delegation.voter_pubkey;
            const old_stake = old_delegation.getStake(
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
            );

            if (!voter_pubkey.equals(&old_voter_pubkey) or stake != old_stake) {
                self.vote_accounts.subStake(old_voter_pubkey, old_stake);
                try self.vote_accounts.addStake(allocator, voter_pubkey, stake);
            }
        } else {
            try self.vote_accounts.addStake(allocator, voter_pubkey, stake);
        }
    }

    pub fn removeVoteAccount(
        self: *Stakes,
        allocator: Allocator,
        pubkey: Pubkey,
    ) void {
        self.vote_accounts.remove(allocator, pubkey);
    }

    pub fn removeStakeAccount(
        self: *Stakes,
        allocator: Allocator,
        pubkey: Pubkey,
        new_rate_activation_epoch: ?Epoch,
    ) void {
        var account = (self.stake_accounts.fetchSwapRemove(pubkey) orelse return).value;
        defer account.deinit(allocator);

        const removed_delegation = account.getDelegation();
        const removed_stake = removed_delegation.getStake(
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
        );

        self.vote_accounts.subStake(removed_delegation.voter_pubkey, removed_stake);
    }
};

const TestStakedNodeAccounts = struct {
    vote_pubkey: Pubkey,
    vote_account: AccountSharedData,
    stake_pubkey: Pubkey,
    stake_account: AccountSharedData,

    pub fn init(allocator: Allocator, random: std.Random, stake: u64) !TestStakedNodeAccounts {
        if (!builtin.is_test) @compileError("only for testing");

        const vote_pubkey, const vote_account = blk: {
            const vote_pubkey = Pubkey.initRandom(random);
            const vote_authority = Pubkey.initRandom(random);
            const vote_account = try vote_accounts.createVoteAccount(
                allocator,
                vote_pubkey,
                vote_authority,
                vote_authority,
                0,
                1,
                null,
            );
            break :blk .{ vote_pubkey, vote_account };
        };
        errdefer allocator.free(vote_account.data);

        const stake_pubkey, const stake_account = blk: {
            const staked_vote_authority = Pubkey.initRandom(random);
            const staked_vote_account = try vote_accounts.createVoteAccount(
                allocator,
                vote_pubkey,
                staked_vote_authority,
                staked_vote_authority,
                0,
                1,
                null,
            );
            defer allocator.free(staked_vote_account.data);

            const stake_pubkey = Pubkey.initRandom(random);
            const stake_account = try stake_accounts.createStakeAccount(
                allocator,
                stake_pubkey,
                vote_pubkey,
                staked_vote_account,
                Rent.FREE,
                stake,
                std.math.maxInt(u64),
            );

            break :blk .{ stake_pubkey, stake_account };
        };

        return .{
            .vote_pubkey = vote_pubkey,
            .vote_account = vote_account,
            .stake_pubkey = stake_pubkey,
            .stake_account = stake_account,
        };
    }

    pub fn deinit(self: TestStakedNodeAccounts, allocator: Allocator) void {
        self.vote_account.deinit(allocator);
        self.stake_account.deinit(allocator);
    }
};

test "stakes basic" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    for (0..1) |i| {
        var stakes_cache = try StakesCache.initEmpty(allocator, i);
        defer stakes_cache.deinit(allocator);

        var accs = try TestStakedNodeAccounts.init(allocator, prng.random(), 10);
        defer accs.deinit(allocator);

        try stakes_cache.checkAndStore(allocator, accs.vote_pubkey, accs.vote_account, null);
        try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, accs.stake_account, null);
        var stake = try stake_accounts.getStakeFromStakeAccount(accs.stake_account);
        {
            const stakes: *Stakes, var stakes_guard = stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(
                stake.delegation.getStake(i, &StakeHistory.EMPTY, null),
                stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
            );
        }

        accs.stake_account.lamports = 42;
        try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, accs.stake_account, null);
        {
            const stakes: *Stakes, var stakes_guard = stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(
                stake.delegation.getStake(i, &StakeHistory.EMPTY, null),
                stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
            );
        }

        const vote_account = try vote_accounts.createVoteAccount(
            allocator,
            Pubkey.initRandom(prng.random()),
            accs.vote_pubkey,
            accs.vote_pubkey,
            0,
            1,
            null,
        );
        defer allocator.free(vote_account.data);

        var stake_account = try stake_accounts.createStakeAccount(
            allocator,
            Pubkey.initRandom(prng.random()),
            accs.vote_pubkey,
            vote_account,
            Rent.FREE,
            42,
            std.math.maxInt(u64),
        );
        defer allocator.free(stake_account.data);

        try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, stake_account, null);
        stake = try stake_accounts.getStakeFromStakeAccount(stake_account);
        {
            const stakes: *Stakes, var stakes_guard = stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(
                stake.delegation.getStake(i, &StakeHistory.EMPTY, null),
                stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
            );
        }

        stake_account.lamports = 0;
        try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, stake_account, null);
        {
            const stakes: *Stakes, var stakes_guard = stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(
                0,
                stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
            );
        }
    }
}
