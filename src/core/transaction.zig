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
