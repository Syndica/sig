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
    account_metas: AccountMetas,
    dedupe_map: [MAX_ACCOUNT_METAS]u16,

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

    /// Caller owns the returned slice.
    /// [agave] https://github.com/anza-xyz/agave/blob/9eee2f66775291a1ec4c4b1be32efc1d314002f7/transaction-context/src/lib.rs#L736
    pub fn getSigners(
        self: *const InstructionInfo,
        allocator: std.mem.Allocator,
    ) error{OutOfMemory}![]Pubkey {
        // [agave] get_signers collects into a HashSet. account_metas may hold
        // up to MAX_INSTR_ACCOUNTS (1094) entries with duplicate pubkeys, so
        // dedupe via an ArrayHashMap (O(1) per probe, insertion-ordered) to
        // keep the result within the distinct-account bound
        // (MAX_ACCOUNT_METAS) instead of an O(n^2) scan.
        // [agave] https://github.com/anza-xyz/agave/blob/v4.0/transaction-context/src/instruction.rs#L253
        var seen: std.AutoArrayHashMapUnmanaged(Pubkey, void) = .empty;
        defer seen.deinit(allocator);
        try seen.ensureTotalCapacity(allocator, MAX_ACCOUNT_METAS);

        for (self.account_metas.items) |account_meta| {
            if (!account_meta.is_signer) continue;
            seen.putAssumeCapacity(account_meta.pubkey, {});
        }
        return allocator.dupe(Pubkey, seen.keys());
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

test "getSigners collects signer keys and excludes non-signers" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var account_metas = InstructionInfo.AccountMetas{};
    defer account_metas.deinit(allocator);

    const signer_a: Pubkey = .initRandom(random);
    const non_signer: Pubkey = .initRandom(random);
    const signer_b: Pubkey = .initRandom(random);

    try account_metas.append(allocator, .{
        .pubkey = signer_a,
        .index_in_transaction = 0,
        .is_signer = true,
        .is_writable = true,
    });
    try account_metas.append(allocator, .{
        .pubkey = non_signer,
        .index_in_transaction = 1,
        .is_signer = false,
        .is_writable = true,
    });
    try account_metas.append(allocator, .{
        .pubkey = signer_b,
        .index_in_transaction = 2,
        .is_signer = true,
        .is_writable = false,
    });

    const ixn_info: InstructionInfo = .{
        .program_meta = .{ .pubkey = Pubkey.ZEROES, .index_in_transaction = 0 },
        .account_metas = account_metas,
        .dedupe_map = @splat(0xffff),
        .instruction_data = "",
        .owned_instruction_data = false,
    };
    const signers = try ixn_info.getSigners(allocator);
    defer allocator.free(signers);

    // Tally result occurrences by seed (byte 0): both signers present once,
    // the non-signer absent.
    var seen: [InstructionInfo.MAX_ACCOUNT_METAS]u8 = @splat(0);
    for (signers) |key| seen[key.data[0]] += 1;

    try std.testing.expectEqual(2, signers.len);
    try std.testing.expectEqual(1, seen[signer_a.data[0]]);
    try std.testing.expectEqual(1, seen[signer_b.data[0]]);
    try std.testing.expectEqual(0, seen[non_signer.data[0]]);
}

// Regression: the conformance/fuzz harness admits instructions with far more
// account metas than MAX_ACCOUNT_METAS (agave's harness caps them at
// MAX_INSTR_ACCOUNTS = 1094). getSigners must dedupe — mirroring agave's
// `get_signers` HashSet — so the distinct signer set stays within
// MAX_ACCOUNT_METAS instead of overflowing the BoundedArray. Before the dedupe
// fix this panicked with "reached unreachable code" on the 257th append.
test "getSigners dedupes duplicate signers without overflowing" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var account_metas = InstructionInfo.AccountMetas{};
    defer account_metas.deinit(allocator);

    // 1094 signer metas (well past MAX_ACCOUNT_METAS) drawn from exactly
    // MAX_ACCOUNT_METAS distinct pubkeys, cycled in order.
    var distinct: [InstructionInfo.MAX_ACCOUNT_METAS]Pubkey = undefined;
    for (&distinct) |*key| key.* = .initRandom(random);

    const meta_count = 1094;
    for (0..meta_count) |i| {
        try account_metas.append(allocator, .{
            .pubkey = distinct[i % InstructionInfo.MAX_ACCOUNT_METAS],
            .index_in_transaction = 0,
            .is_signer = true,
            .is_writable = false,
        });
    }

    const ixn_info: InstructionInfo = .{
        .program_meta = .{ .pubkey = Pubkey.ZEROES, .index_in_transaction = 0 },
        .account_metas = account_metas,
        .dedupe_map = @splat(0xffff),
        .instruction_data = "",
        .owned_instruction_data = false,
    };
    const signers = try ixn_info.getSigners(allocator);
    defer allocator.free(signers);

    try std.testing.expectEqual(InstructionInfo.MAX_ACCOUNT_METAS, signers.len);
    var seen: std.AutoHashMapUnmanaged(Pubkey, void) = .empty;
    defer seen.deinit(allocator);
    for (signers) |key| try seen.put(allocator, key, {});
    try std.testing.expectEqual(InstructionInfo.MAX_ACCOUNT_METAS, seen.count());
    for (distinct) |key| try std.testing.expect(seen.contains(key));
}
