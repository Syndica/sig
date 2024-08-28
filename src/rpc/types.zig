const std = @import("std");

pub const Commitment = enum {
    finalized,
    confirmed,
    processed,
};

pub const AccountInfo = struct {
    context: Context,
    value: Value,

    const Context = struct {
        slot: u64,
        apiVersion: []const u8,
    };

    const Value = struct {
        data: []const u8,
        executable: bool,
        lamports: u64,
        owner: []const u8,
        rentEpoch: u64,
        space: u64,
    };
};

pub const Balance = struct {
    context: Context,
    value: u64,

    const Context = struct {
        slot: u64,
        apiVersion: []const u8,
    };

    pub fn deinit(self: *const Balance, allocator: std.mem.Allocator) void {
        allocator.free(self.context.apiVersion);
    }
};

pub const Block = struct {
    blockhash: []const u8,
    previousBlockhash: []const u8,
    parentSlot: u64,
    blockTime: ?u64 = null,
    blockHeight: ?u64 = null,
    transactions: ?[]const _Transaction = null,
    signatures: ?[]const _Signature = null,
    rewards: ?[]const _Rewards = null,

    const _Transaction = struct {
        // TODO: Implement
    };

    const _Signature = struct {
        // TODO: Implement
    };

    const _Rewards = struct {
        pubkey: []const u8,
        lamports: u64,
        postBalance: u64,
        rewardType: ?[]const u8,
        commission: ?u8,
    };
};

pub const BlockCommitment = struct {
    commitment: ?[]const u64,
    totalStake: u64,
};

pub const EpochInfo = struct {
    absoluteSlot: u64,
    blockHeight: u64,
    epoch: u64,
    slotIndex: u64,
    slotsInEpoch: u64,
    transactionCount: u64,
};

pub const LatestBlockhash = struct {
    context: Context,
    value: Value,

    const Context = struct {
        slot: u64,
        apiVersion: []const u8,
    };

    const Value = struct {
        blockhash: []const u8,
        lastValidBlockHeight: u64,
    };
};

pub const LeaderSchedule = std.StringArrayHashMap([]const u64);

pub const SignatureStatuses = struct {
    context: Context,
    value: []const ?Status,

    pub const Context = struct {
        apiVersion: []const u8,
        slot: u64,
    };

    pub const Status = struct {
        slot: u64,
        confirmations: ?usize,
        err: ?[]const u8,
        confirmationStatus: ?[]const u8,
    };
};
