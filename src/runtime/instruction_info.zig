const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;

/// Intruction information which is constant across instruction execution
/// [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/info/fd_instr_info.h#L14-L15
pub const InstructionInfo = struct {
    program_meta: ProgramMeta,
    account_metas: std.BoundedArray(AccountMeta, MAX_ACCOUNT_METAS),
    instruction_data: []const u8,
    // Initial account lamports are computed and set immediately before
    // pushing an instruction onto the stack.
    initial_account_lamports: u128 = 0,

    /// [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/info/fd_instr_info.h#L12
    pub const MAX_ACCOUNT_METAS: usize = 256;

    pub const ProgramMeta = struct {
        pubkey: Pubkey,
        index_in_transaction: u16,
    };

    pub const AccountMeta = struct {
        pubkey: Pubkey,
        index_in_transaction: u16,
        // Non Cpi:
        // - the index of the account in the transaction
        // - [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/svm/src/message_processor.rs#L63
        // Cpi:
        // - the index of the account in the calling instruction context
        // - [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L363-L376
        index_in_caller: u16,
        // Non Cpi:
        // - the first index of the account in the called instruction context
        // - [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/svm/src/message_processor.rs#L52-L60
        // Cpi:
        // - the index of the account in the called instruction context
        // - [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L380
        index_in_callee: u16,
        is_signer: bool,
        is_writable: bool,
    };

    pub fn deinit(self: InstructionInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.instruction_data);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L523
    pub fn getAccountMetaIndex(
        self: InstructionInfo,
        pubkey: Pubkey,
    ) ?u16 {
        for (self.account_metas.slice(), 0..) |account_meta, index|
            if (account_meta.pubkey.equals(&pubkey)) return @intCast(index);
        return null;
    }

    // Gets the account meta at a given index returning null if the index is out of bounds
    pub fn getAccountMetaAtIndex(
        self: InstructionInfo,
        index: u16,
    ) ?*const InstructionInfo.AccountMeta {
        if (index >= self.account_metas.len) return null;
        return &self.account_metas.buffer[index];
    }

    /// Return if the account at a given index is a signer with bounds checking
    pub fn isIndexSigner(
        self: InstructionInfo,
        index: u16,
    ) InstructionError!bool {
        const account_meta = self.getAccountMetaAtIndex(index) orelse
            return InstructionError.NotEnoughAccountKeys;
        return account_meta.is_signer;
    }

    /// Replaces Agave's approach to checking if a pubkey is a signer which is to precompute a
    /// hashmap of signers to parse during instruction execution
    pub fn isPubkeySigner(
        self: InstructionInfo,
        pubkey: Pubkey,
    ) bool {
        for (self.account_metas.slice()) |account_meta|
            if (account_meta.pubkey.equals(&pubkey) and account_meta.is_signer) return true;
        return false;
    }

    /// Agave https://github.com/anza-xyz/agave/blob/9eee2f66775291a1ec4c4b1be32efc1d314002f7/transaction-context/src/lib.rs#L736
    ///
    /// Fill in the passed buffer with all keys of signer instruction accounts in this Instruction.
    pub fn signers(self: *const InstructionInfo, buffer: *std.ArrayList(Pubkey)) !void {
        for (self.account_metas.constSlice()) |account_meta| {
            if (account_meta.is_signer) {
                try buffer.append(account_meta.pubkey);
            }
        }
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/program_utils.rs#L9
    pub fn deserializeInstruction(
        self: InstructionInfo,
        allocator: std.mem.Allocator,
        comptime T: type,
    ) InstructionError!T {
        if (self.instruction_data.len > Transaction.MAX_BYTES)
            return InstructionError.InvalidInstructionData;
        return bincode.readFromSlice(allocator, T, self.instruction_data, .{}) catch {
            return InstructionError.InvalidInstructionData;
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L493
    pub fn checkNumberOfAccounts(
        self: InstructionInfo,
        minimum_accounts: u16,
    ) InstructionError!void {
        if (self.account_metas.len < minimum_accounts) return InstructionError.NotEnoughAccountKeys;
    }
};

test "deserializeInstruction: invalid instruction data" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const DummyInstruction = struct { data: []const u8 };

    const dummy_instruction: DummyInstruction = .{
        .data = &[_]u8{0} ** (Transaction.MAX_BYTES + 10),
    };

    const instruction_info: InstructionInfo = .{
        .program_meta = .{
            .pubkey = Pubkey.initRandom(prng.random()),
            .index_in_transaction = 0,
        },
        .account_metas = .{},
        .instruction_data = try bincode.writeAlloc(
            allocator,
            dummy_instruction,
            .{},
        ),
        .initial_account_lamports = 0,
    };
    defer instruction_info.deinit(allocator);

    try std.testing.expectError(
        InstructionError.InvalidInstructionData,
        instruction_info.deserializeInstruction(allocator, u32),
    );
}
