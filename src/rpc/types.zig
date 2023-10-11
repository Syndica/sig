const Account = @import("../core/account.zig").Account;
const std = @import("std");
const base64 = std.base64.standard;
const Pubkey = @import("../core/pubkey.zig").Pubkey;

pub fn ValueWithContext(comptime Value: anytype) type {
    return struct {
        context: struct {
            slot: u64,
            apiVersion: []const u8,
        },
        value: Value,
    };
}

pub const Encoding = enum {
    Base64,
    Base58,
    Json,
    JsonParsed,

    const Self = @This();

    pub fn string(self: Self) []const u8 {
        switch (self) {
            .Base64 => {
                return "base64";
            },
            .Base58 => {
                return "base58";
            },
            .Json => {
                return "json";
            },
            .JsonParsed => {
                return "jsonParsed";
            },
        }
    }
};

pub const Commitment = enum {
    Finalized,
    Confirmed,
    Processed,

    const Self = @This();

    pub fn string(self: Self) []const u8 {
        switch (self) {
            .Finalized => {
                return "finalized";
            },
            .Confirmed => {
                return "confirmed";
            },
            .Processed => {
                return "processed";
            },
        }
    }
};

const AccountValue = struct {
    lamports: u64,
    data: [][]const u8,
    owner: []const u8,
    executable: bool,
    rent_epoch: u64,

    const Self = @This();

    const Error = error{
        DataNotBase64,
    };

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.destroy(self.data);
        allocator.destroy(self.owner);
    }

    pub fn intoAccount(self: Self, allocator: std.mem.Allocator) !Account {
        if (std.mem.eql(u8, &self.data[1], &Encoding.Base64.string())) {
            const data_size = try base64.Decoder.calcSizeForSlice(self.data[0]);
            const data_decoded = try allocator.alloc(u8, data_size);
            try base64.Decoder.decode(data_decoded, self.data[0]);

            var owner = try Pubkey.fromString(allocator, self.owner);

            return Account{
                .lamports = self.lamports,
                .data = data_decoded,
                .owner = owner,
                .executable = self.executable,
                .rent_epoch = self.rent_epoch,
            };
        }

        return Error.DataNotBase64;
    }
};

pub const BlockInfo = struct {
    blockHeight: ?u64,
    blockTime: ?u64,
    blockhash: []const u8,
    parentSlot: u64,
    previousBlockhash: []const u8,
    transactions: []Transaction,
};

pub const AccountInfo = ValueWithContext(AccountValue);

pub const BalanceInfo = ValueWithContext(u64);

pub const BlockProductionInfo = ValueWithContext(BlockProduction);

pub const BlockCommitment = struct {
    commitment: ?[]u64,
    totalStake: u64,
};

pub const BlockProduction = struct {
    byIdentity: std.StringArrayHashMap([]u64),
    range: struct {
        firstSlot: u64,
        lastSlot: u64,
    },
};

pub const NodeInfo = struct {
    gossip: []const u8,
    pubkey: []const u8,
    rpc: []const u8,
    tpu: []const u8,
    version: []const u8,
};

pub const EpochInfo = struct {
    absoluteSlot: u64,
    blockHeight: u64,
    epoch: u64,
    slotIndex: u64,
    slotsInEpoch: u64,
    transactionCount: u64,
};

pub const SnapshotInfo = struct { full: u64, incremental: ?u64 };

pub const IdentityInfo = struct { identity: []const u8 };

pub const InfaltionInfo = struct {
    foundation: f64,
    foundationTerm: f64,
    initial: f64,
    taper: f64,
    terminal: f64,
};

pub const InflationRateInfo = struct {
    epoch: f64,
    foundation: f64,
    total: f64,
    validator: f64,
};

pub const InflationReward = struct {
    amount: u64,
    effectiveSlot: u64,
    epoch: u64,
    postBalance: u64,
    commission: ?u64,
};

pub const EpochSchedule = struct {
    firstNormalEpoch: u64,
    firstNormalSlot: u64,
    leaderScheduleSlotOffset: u64,
    slotsPerEpoch: u64,
    warmup: bool,
};

pub const MessageFeeInfo = ValueWithContext(?u64);

pub const LargeAccount = struct {
    address: []const u8,
    lamports: u64,
};

pub const LargestAccountsInfo = ValueWithContext([]LargeAccount);

pub const LatestBlockhash = struct {
    blockhash: []const u8,
    lastValidBlockHeight: u64,
};

pub const LatestBlockhashInfo = ValueWithContext(LatestBlockhash);

pub const MultipleAccountsInfo = ValueWithContext([]?AccountValue);

pub const IdentifiedAccountInfos = ValueWithContext([]struct { account: AccountValue, pubkey: []const u8 });

pub const PerformanceSample = struct {
    numSlots: u64,
    numTransactions: u64,
    // TODO: available from version >= 1.15
    // numNonVoteTransaction: ?u64,
    samplePeriodSecs: u64,
    slot: u64,
};

pub const PrioritizationFeeInfo = struct { slot: u64, prioritizationFee: u64 };

pub const SignatureInfo = struct {
    err: ?[]const u8,
    memo: ?[]const u8,
    signature: []const u8,
    slot: u64,
    blockTime: ?i64,
    confirmationStatus: ?[]const u8,
};

pub const SignatureStatus = struct {
    slot: u64,
    confirmations: ?u64,
    err: ?[]const u8,
    status: ?struct { Ok: ?u8, Err: ?[]const u8 = null },
    confirmationStatus: ?[]const u8,
};

pub const SignatureStatusesInfo = ValueWithContext([]?SignatureStatus);

pub const StakeActivation = struct {
    active: u64,
    inactive: u64,
    state: []const u8,
};

pub const StakeMinimumDelegationInfo = ValueWithContext(u64);

pub const Supply = struct {
    circulating: u64,
    nonCirculating: u64,
    nonCirculatingAccounts: [][]const u8,
    total: u64,
};

pub const SupplyInfo = ValueWithContext(Supply);

pub const TokenAccountBalance = struct {
    amount: []const u8,
    decimals: u8,
    uiAmount: f32,
    uiAmountString: []const u8,
};

pub const TokenAccountBalanceInfo = ValueWithContext(TokenAccountBalance);

pub const TokenAccountBalanceInfos = ValueWithContext([]TokenAccountBalance);

pub const VersionInfo = struct {
    @"solana-core": []const u8,
    @"feature-set": u64,
};

pub const VoteAccount = struct {
    commission: u64,
    epochVoteAccount: bool,
    epochCredits: [][]u64,
    nodePubkey: []const u8,
    lastVote: u64,
    activatedStake: u64,
    votePubkey: []const u8,
};

pub const VoteAccountsInfo = struct {
    current: []VoteAccount,
    delinquent: []VoteAccount,
};

pub const BlockhashInfo = ValueWithContext(bool);

pub const SimulatedTransaction = struct {
    err: ?[]const u8 = null,
    accounts: ?[]?AccountValue = null,
    logs: [][]const u8,
    returnData: ?struct {
        data: [][]const u8,
        programId: []const u8,
    } = null,
    unitsConsumed: u64,
};

pub const SimulatedTransactionInfo = ValueWithContext(SimulatedTransaction);

const InnerInstruction = struct {
    programIdIndex: u16,
    accounts: []u16,
    data: []const u8,
};

const BlockReward = struct {
    pubkey: []const u8,
    lamports: u64,
    postBalance: u64,
    rewardType: ?[]const u8,
    commission: ?u8,
};

const Instruction = struct {
    accounts: []u16,
    data: []const u8,
    programIdIndex: u16,
};

pub const Transaction = struct {
    meta: ?struct {
        // TODO: figure out error enum object
        err: ?u8,
        fee: u64,
        innerInstructions: []InnerInstruction,
        logMessages: ?[][]const u8,
        postBalances: ?[]u64,
        postTokenBalances: ?[]u64,
        preBalances: ?[]u64,
        preTokenBalances: ?[]u64,
        rewards: ?[]BlockReward,
        /// NOTE: deprecated
        status: struct {
            Ok: ?u8 = null,
            Err: ?[]const u8 = null,
        },
    },
    transaction: struct {
        message: struct {
            accountKeys: [][]const u8,
            header: struct {
                numReadonlySignedAccounts: u16,
                numReadonlyUnsignedAccounts: u16,
                numRequiredSignatures: u16,
            },
            instructions: []Instruction,
            recentBlockhash: []const u8,
        },
        signatures: [][]const u8,
    },
};
