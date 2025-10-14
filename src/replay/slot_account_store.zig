const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const program = sig.runtime.program;
const builtin_programs = sig.runtime.program.builtin_programs;

const AccountStore = sig.accounts_db.AccountStore;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const SlotState = sig.core.SlotState;
const AccountSharedData = sig.runtime.AccountSharedData;

pub const SlotAccountStore = struct {
    slot: Slot,
    state: *SlotState,
    writer: AccountStore,
    reader: SlotAccountReader,

    pub fn init(
        slot: Slot,
        state: *SlotState,
        writer: AccountStore,
        ancestors: *const Ancestors,
    ) SlotAccountStore {
        return .{
            .slot = slot,
            .state = state,
            .writer = writer,
            .reader = writer.reader().forSlot(ancestors),
        };
    }

    pub fn get(self: *const SlotAccountStore, key: Pubkey) !?Account {
        return self.reader.get(key);
    }

    pub fn put(
        self: SlotAccountStore,
        key: Pubkey,
        account: AccountSharedData,
    ) !void {
        try self.writer.put(self.slot, key, account);
    }

    pub fn putAndUpdateCapitalization(
        self: SlotAccountStore,
        key: Pubkey,
        new_account: AccountSharedData,
    ) !void {
        const old_account_data_len = if (try self.get(key)) |old_account| blk: {
            const diff = if (new_account.lamports > old_account.lamports)
                new_account.lamports - old_account.lamports
            else
                old_account.lamports - new_account.lamports;
            _ = self.state.capitalization.fetchSub(diff, .monotonic);
            break :blk old_account.data.len();
        } else blk: {
            _ = self.state.capitalization.fetchAdd(new_account.lamports, .monotonic);
            break :blk 0;
        };

        try self.put(key, new_account);

        // NOTE: update account size delta in slot state?
        _ = old_account_data_len;
    }

    pub fn burnAndPurgeAccount(self: SlotAccountStore, key: Pubkey, account: AccountSharedData) !void {
        const account_data_len = account.data.len;

        _ = self.state.capitalization.fetchSub(account.lamports, .monotonic);
        var acc = account;
        acc.lamports = 0;
        @memset(acc.data, 0);
        try self.put(key, acc);

        // NOTE: update account size delta in slot state?
        _ = account_data_len;
    }

    pub fn putPrecompile(
        self: SlotAccountStore,
        allocator: Allocator,
        precompile: program.precompiles.Precompile,
    ) !void {
        const maybe_account = try self.get(precompile.program_id);
        defer if (maybe_account) |account| account.deinit(allocator);

        if (maybe_account) |account| if (!account.executable) {
            try self.burnAndPurgeAccount(
                precompile.program_id,
                try AccountSharedData.fromAccount(allocator, &account),
            );
        } else return;

        // assert!(!self.freeze_started()); NOTE: Do we need this?

        const lamports, const rent_epoch = inheritLamportsAndRentEpoch(maybe_account);

        try self.putAndUpdateCapitalization(
            precompile.program_id,
            .{
                .lamports = lamports,
                .data = &.{},
                .executable = true,
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                .rent_epoch = rent_epoch,
            },
        );
    }

    pub fn putBuiltinProgramAccount(
        self: SlotAccountStore,
        allocator: Allocator,
        builtin_program: builtin_programs.BuiltinProgram,
    ) !void {
        if (try self.reader.get(builtin_program.program_id)) |account| {
            if (sig.runtime.ids.NATIVE_LOADER_ID.equals(&account.owner)) return;
            const account_shared_data = try AccountSharedData.fromAccount(allocator, &account);
            defer allocator.free(account_shared_data.data);
            try self.burnAndPurgeAccount(builtin_program.program_id, account_shared_data);
        }

        const lamports, const rent_epoch = inheritLamportsAndRentEpoch(null);
        const account: AccountSharedData = .{
            .lamports = lamports,
            .data = try allocator.dupe(u8, builtin_program.data),
            .executable = true,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .rent_epoch = rent_epoch,
        };
        defer allocator.free(account.data);

        try self.putAndUpdateCapitalization(builtin_program.program_id, account);
    }

    fn inheritLamportsAndRentEpoch(
        maybe_account: ?Account,
    ) struct { u64, u64 } {
        return if (maybe_account) |account|
            .{ account.lamports, account.rent_epoch }
        else
            .{ 1, 0 };
    }
};
