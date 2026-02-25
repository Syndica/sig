const std = @import("std");
const std14 = @import("std14");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;

/// Intruction information which is constant across instruction execution
/// [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/info/fd_instr_info.h#L14-L15
pub const InstructionInfo = struct {
    program_meta: ProgramMeta,
    account_metas: AccountMetas,
    dedupe_map: [MAX_ACCOUNT_METAS]u8,

    instruction_data: []const u8,
    owned_instruction_data: bool,

    // Initial account lamports are computed and set immediately before
    // pushing an instruction onto the stack.
    initial_account_lamports: u128 = 0,

    /// [agave] https://github.com/anza-xyz/agave/blob/v3.0/transaction-context/src/lib.rs#L23
    pub const MAX_ACCOUNT_METAS = 256;

    /// Errors resulting from instructions with account metas > MAX_ACCOUNT_METAS are handled during
    /// transaction execution. We construct the account metas before transaction execution, so using an
    /// array of size MAX_ACCOUNTS_METAS + 1 allows us to check the account metas length during transaction
    /// execution and return the appropriate error.
    pub const AccountMetas = std.ArrayListUnmanaged(AccountMeta);

    pub const ProgramMeta = struct {
        pubkey: Pubkey,
        index_in_transaction: u16,
    };

    pub const AccountMeta = struct {
        pubkey: Pubkey,
        index_in_transaction: u16,
        is_signer: bool,
        is_writable: bool,
    };

    pub fn deinit(self: InstructionInfo, allocator: std.mem.Allocator) void {
        if (self.owned_instruction_data) allocator.free(self.instruction_data);

        var account_metas = self.account_metas;
        account_metas.deinit(allocator);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/v3.0/transaction-context/src/lib.rs#L690
    pub fn getAccountInstructionIndex(
        self: *const InstructionInfo,
        index_in_transaction: u16,
    ) InstructionError!u16 {
        if (index_in_transaction < self.dedupe_map.len) {
            const index = self.dedupe_map[index_in_transaction];
            if (index < self.account_metas.items.len) {
                return index;
            }
        }
        return error.MissingAccount;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L523
    pub fn getAccountMetaIndex(
        self: *const InstructionInfo,
        pubkey: Pubkey,
    ) ?u16 {
        for (self.account_metas.items, 0..) |account_meta, index|
            if (account_meta.pubkey.equals(&pubkey)) return @intCast(index);
        return null;
    }

    // Gets the account meta at a given index returning null if the index is out of bounds
    pub fn getAccountMetaAtIndex(
        self: *const InstructionInfo,
        index: u16,
    ) ?*const InstructionInfo.AccountMeta {
        if (index >= self.account_metas.items.len) return null;
        return &self.account_metas.items[index];
    }

    /// Return if the account at a given index is a signer with bounds checking
    pub fn isIndexSigner(
        self: *const InstructionInfo,
        index: u16,
    ) InstructionError!bool {
        const account_meta = self.getAccountMetaAtIndex(index) orelse
            return InstructionError.MissingAccount;
        return account_meta.is_signer;
    }

    /// Replaces Agave's approach to checking if a pubkey is a signer which is to precompute a
    /// hashmap of signers to parse during instruction execution
    pub fn isPubkeySigner(
        self: *const InstructionInfo,
        pubkey: Pubkey,
    ) bool {
        for (self.account_metas.items) |account_meta|
            if (account_meta.pubkey.equals(&pubkey) and account_meta.is_signer) return true;
        return false;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/9eee2f66775291a1ec4c4b1be32efc1d314002f7/transaction-context/src/lib.rs#L736
    pub fn getSigners(
        self: *const InstructionInfo,
    ) std14.BoundedArray(Pubkey, MAX_ACCOUNT_METAS) {
        var signers = std14.BoundedArray(Pubkey, MAX_ACCOUNT_METAS){};
        for (self.account_metas.items) |account_meta| {
            if (account_meta.is_signer) {
                signers.appendAssumeCapacity(account_meta.pubkey);
            }
        }
        return signers;
    }

    pub fn instructionDataToDeserialize(self: *const InstructionInfo) []const u8 {
        return self.instruction_data[0..@min(
            self.instruction_data.len,
            Transaction.MAX_BYTES,
        )];
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/program_utils.rs#L9
    pub fn deserializeInstruction(
        self: *const InstructionInfo,
        allocator: std.mem.Allocator,
        comptime T: type,
    ) InstructionError!T {
        var fbs = std.io.fixedBufferStream(self.instructionDataToDeserialize());
        const data = bincode.read(allocator, T, fbs.reader(), .{}) catch {
            return InstructionError.InvalidInstructionData;
        };
        return data;
    }

    /// Identical to deserializeInstruction but using `alloc_buf` to avoid heap allocation.
    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/1276772ee61fbd1f8a60cfec7cd553aa4f6a55f3/bincode/src/lib.rs#L9
    pub fn limitedDeserializeInstruction(
        self: *const InstructionInfo,
        comptime T: type,
        alloc_buf: []u8,
    ) InstructionError!T {
        var fbs = std.io.fixedBufferStream(self.instructionDataToDeserialize());
        var fba = std.heap.FixedBufferAllocator.init(alloc_buf);
        return bincode.read(fba.allocator(), T, fbs.reader(), .{}) catch {
            return InstructionError.InvalidInstructionData;
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L493
    pub fn checkNumberOfAccounts(
        self: *const InstructionInfo,
        minimum_accounts: u16,
    ) InstructionError!void {
        if (self.account_metas.items.len < minimum_accounts)
            return InstructionError.MissingAccount;
    }
};
