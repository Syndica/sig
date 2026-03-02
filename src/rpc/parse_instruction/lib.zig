//! Instruction parsers for jsonParsed encoding mode.
//!
//! Parses compiled instructions from known programs (vote, system, spl-memo)
//! into structured JSON representations matching Agave's output format.
//! Unknown programs fall back to partially decoded representation.

const std = @import("std");
const sig = @import("../../sig.zig");
const base58 = @import("base58");
pub const AccountKeys = @import("AccountKeys.zig");

const Allocator = std.mem.Allocator;
const JsonValue = std.json.Value;
const ObjectMap = std.json.ObjectMap;

const AddressLookupTableInstruction = sig.runtime.program.address_lookup_table.Instruction;
const BpfUpgradeableLoaderInstruction = sig.runtime.program.bpf_loader.v3.Instruction;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const StakeAuthorize = sig.runtime.program.stake.state.StakeStateV2.StakeAuthorize;
const StakeInstruction = sig.runtime.program.stake.Instruction;
const StakeLockupArgs = sig.runtime.program.stake.LockupArgs;
const SystemInstruction = sig.runtime.program.system.Instruction;

/// SPL Associated Token Account program ID
const SPL_ASSOCIATED_TOKEN_ACC_ID: Pubkey = .parse("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// SPL Memo v1 program ID
const SPL_MEMO_V1_ID: Pubkey = .parse("Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo");
/// SPL Memo v3 program ID
const SPL_MEMO_V3_ID: Pubkey = .parse("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

/// BPF Loader v2 instruction enum (bincode serialized u32)
const BpfLoaderInstruction = union(enum(u32)) {
    /// Write program data into a Buffer account.
    /// # Account references
    ///   0. `[writable]` Account to write to
    write: struct {
        offset: u32,
        bytes: []const u8,
    },
    /// Finalize a program (make it executable)
    /// # Account references
    ///   0. `[writable, signer]` The program account
    ///   1. `[]` Rent sysvar
    finalize,
};

/// Associated Token Account instruction enum (borsh serialized u8)
const AssociatedTokenAccountInstruction = enum(u8) {
    /// Create an associated token account for the given wallet address and token mint.
    /// Accounts:
    ///   0. `[writeable, signer]` Funding account
    ///   1. `[writeable]` Associated token account address
    ///   2. `[]` Wallet address for the account
    ///   3. `[]` The token mint
    ///   4. `[]` System program
    ///   5. `[]` SPL Token program
    create = 0,
    /// Create an associated token account for the given wallet address and token mint,
    /// if it doesn't already exist.
    create_idempotent = 1,
    /// Recover nested associated token account.
    recover_nested = 2,
};

pub const ParsableProgram = enum {
    addressLookupTable,
    splAssociatedTokenAccount,
    splMemo,
    splToken,
    bpfLoader,
    bpfUpgradeableLoader,
    stake,
    system,
    vote,

    pub const PARSABLE_PROGRAMS = [_]struct { Pubkey, ParsableProgram }{
        .{
            sig.runtime.program.address_lookup_table.ID,
            .addressLookupTable,
        },
        .{
            SPL_ASSOCIATED_TOKEN_ACC_ID,
            .splAssociatedTokenAccount,
        },
        .{ SPL_MEMO_V1_ID, .splMemo },
        .{ SPL_MEMO_V3_ID, .splMemo },
        .{ sig.runtime.program.bpf_loader.v2.ID, .bpfLoader },
        .{ sig.runtime.program.bpf_loader.v3.ID, .bpfUpgradeableLoader },
        .{ sig.runtime.program.stake.ID, .stake },
        .{ sig.runtime.program.system.ID, .system },
        .{ sig.runtime.program.vote.ID, .vote },
        .{ sig.runtime.ids.TOKEN_PROGRAM_ID, .splToken },
        .{ sig.runtime.ids.TOKEN_2022_PROGRAM_ID, .splToken },
    };

    pub fn fromID(program_id: Pubkey) ?ParsableProgram {
        inline for (PARSABLE_PROGRAMS) |entry| {
            if (program_id.equals(&entry[0])) return entry[1];
        }
        return null;
    }
};

pub const UiInnerInstructions = struct {
    index: u8,
    instructions: []const UiInstruction,

    pub fn jsonStringify(self: UiInnerInstructions, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("index");
        try jw.write(self.index);
        try jw.objectField("instructions");
        try jw.beginArray();
        for (self.instructions) |ixn| {
            try ixn.jsonStringify(jw);
        }
        try jw.endArray();
        try jw.endObject();
    }
};

pub const UiInstruction = union(enum) {
    compiled: UiCompiledInstruction,
    parsed: *const UiParsedInstruction,

    pub fn jsonStringify(self: UiInstruction, jw: anytype) !void {
        switch (self) {
            .compiled => |c| try c.jsonStringify(jw),
            .parsed => |p| try p.jsonStringify(jw),
        }
    }
};

pub const UiParsedInstruction = union(enum) {
    parsed: ParsedInstruction,
    partially_decoded: UiPartiallyDecodedInstruction,

    pub fn jsonStringify(self: UiParsedInstruction, jw: anytype) !void {
        switch (self) {
            .parsed => |p| try p.jsonStringify(jw),
            .partially_decoded => |pd| try pd.jsonStringify(jw),
        }
    }
};

pub const UiCompiledInstruction = struct {
    programIdIndex: u8,
    accounts: []const u8,
    data: []const u8,
    stackHeight: ?u32 = null,

    pub fn jsonStringify(self: UiCompiledInstruction, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("accounts");
        try writeByteArrayAsJsonArray(jw, self.accounts);
        try jw.objectField("data");
        try jw.write(self.data);
        try jw.objectField("programIdIndex");
        try jw.write(self.programIdIndex);
        if (self.stackHeight) |sh| {
            try jw.objectField("stackHeight");
            try jw.write(sh);
        }
        try jw.endObject();
    }

    fn writeByteArrayAsJsonArray(jw: anytype, bytes: []const u8) @TypeOf(jw.*).Error!void {
        try jw.beginArray();
        for (bytes) |b| {
            try jw.write(b);
        }
        try jw.endArray();
    }
};

pub const UiPartiallyDecodedInstruction = struct {
    programId: []const u8,
    accounts: []const []const u8,
    data: []const u8,
    stackHeight: ?u32 = null,

    pub fn jsonStringify(self: UiPartiallyDecodedInstruction, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("accounts");
        try jw.write(self.accounts);
        try jw.objectField("data");
        try jw.write(self.data);
        try jw.objectField("programId");
        try jw.write(self.programId);
        if (self.stackHeight) |sh| {
            try jw.objectField("stackHeight");
            try jw.write(sh);
        }
        try jw.endObject();
    }
};

/// A parsed or partially-decoded instruction for jsonParsed mode.
/// In jsonParsed mode, known programs produce structured parsed output,
/// while unknown programs fall back to partially decoded representation.
pub const ParsedInstruction = struct {
    /// Program name: "vote", "system", "spl-memo"
    program: []const u8,
    /// Program ID as base58 string
    program_id: []const u8,
    /// Pre-serialized JSON for the "parsed" field.
    /// For vote/system: `{"type":"...", "info":{...}}`
    /// For spl-memo: `"<memo text>"`
    parsed: std.json.Value,
    /// Stack height
    stack_height: ?u32 = null,

    pub fn jsonStringify(self: ParsedInstruction, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("parsed");
        try jw.write(self.parsed);
        try jw.objectField("program");
        try jw.write(self.program);
        try jw.objectField("programId");
        try jw.write(self.program_id);
        if (self.stack_height) |sh| {
            try jw.objectField("stackHeight");
            try jw.write(sh);
        }
        try jw.endObject();
    }
};

fn allocParsed(
    arena: Allocator,
    value: UiParsedInstruction,
) !UiInstruction {
    const ptr = try arena.create(UiParsedInstruction);
    ptr.* = value;
    return .{ .parsed = ptr };
}

pub fn parseUiInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
    stack_height: ?u32,
) !UiInstruction {
    const ixn_idx: usize = @intCast(instruction.program_id_index);
    const program_id = account_keys.get(ixn_idx).?;
    return parseInstruction(
        arena,
        program_id,
        instruction,
        account_keys,
        stack_height,
    ) catch {
        return allocParsed(arena, .{ .partially_decoded = try makeUiPartiallyDecodedInstruction(
            arena,
            instruction,
            account_keys,
            stack_height,
        ) });
    };
}

pub fn parseUiInnerInstructions(
    arena: Allocator,
    inner_instructions: sig.ledger.transaction_status.InnerInstructions,
    account_keys: *const AccountKeys,
) !UiInnerInstructions {
    var instructions = try arena.alloc(UiInstruction, inner_instructions.instructions.len);
    for (inner_instructions.instructions, 0..) |ixn, i| {
        instructions[i] = try parseUiInstruction(
            arena,
            ixn.instruction,
            account_keys,
            ixn.stack_height,
        );
    }
    return .{
        .index = inner_instructions.index,
        .instructions = instructions,
    };
}

/// Try to parse a compiled instruction into a structured parsed instruction.
/// Falls back to partially decoded representation on failure.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_instruction.rs#L95
pub fn parseInstruction(
    arena: Allocator,
    program_id: Pubkey,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
    stack_height: ?u32,
) !UiInstruction {
    const program_name = ParsableProgram.fromID(program_id) orelse return error.ProgramNotParsable;

    switch (program_name) {
        .addressLookupTable => {
            return allocParsed(arena, .{ .parsed = .{
                .program = "address-lookup-table",
                .program_id = try arena.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseAddressLookupTableInstruction(
                    arena,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .splAssociatedTokenAccount => {
            return allocParsed(arena, .{ .parsed = .{
                .program = "spl-associated-token-account",
                .program_id = try arena.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseAssociatedTokenInstruction(
                    arena,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .splMemo => {
            return allocParsed(arena, .{ .parsed = .{
                .program = "spl-memo",
                .program_id = try arena.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseMemoInstruction(arena, instruction.data),
                .stack_height = stack_height,
            } });
        },
        .splToken => {
            return allocParsed(arena, .{ .parsed = .{
                .program = "spl-token",
                .program_id = try arena.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseTokenInstruction(
                    arena,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .bpfLoader => {
            return allocParsed(arena, .{ .parsed = .{
                .program = "bpf-loader",
                .program_id = try arena.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseBpfLoaderInstruction(
                    arena,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .bpfUpgradeableLoader => {
            return allocParsed(arena, .{ .parsed = .{
                .program = "bpf-upgradeable-loader",
                .program_id = try arena.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseBpfUpgradeableLoaderInstruction(
                    arena,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .stake => {
            return allocParsed(arena, .{ .parsed = .{
                .program = @tagName(program_name),
                .program_id = try arena.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseStakeInstruction(
                    arena,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .system => {
            return allocParsed(arena, .{ .parsed = .{
                .program = @tagName(program_name),
                .program_id = try arena.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseSystemInstruction(
                    arena,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .vote => {
            return allocParsed(arena, .{ .parsed = .{
                .program = @tagName(program_name),
                .program_id = try arena.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseVoteInstruction(
                    arena,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
    }
}

/// Fallback decoded representation of a compiled instruction
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L96
pub fn makeUiPartiallyDecodedInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
    stack_height: ?u32,
) !UiPartiallyDecodedInstruction {
    const program_id_index: usize = @intCast(instruction.program_id_index);
    const program_id_str = if (account_keys.get(program_id_index)) |pk|
        try arena.dupe(u8, pk.base58String().constSlice())
    else
        try arena.dupe(u8, "unknown");

    var accounts = try arena.alloc([]const u8, instruction.accounts.len);
    for (instruction.accounts, 0..) |acct_idx, i| {
        accounts[i] = if (account_keys.get(@intCast(acct_idx))) |pk|
            try arena.dupe(u8, pk.base58String().constSlice())
        else
            try arena.dupe(u8, "unknown");
    }

    return .{
        .programId = program_id_str,
        .accounts = accounts,
        .data = blk: {
            const buf = try arena.alloc(u8, base58.encodedMaxSize(instruction.data.len));
            const len = base58.Table.BITCOIN.encode(buf, instruction.data);
            break :blk try arena.dupe(u8, buf[0..len]);
        },
        .stackHeight = stack_height,
    };
}

/// Parse an SPL Memo instruction. The data is simply UTF-8 text.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_instruction.rs#L131
fn parseMemoInstruction(arena: Allocator, data: []const u8) !JsonValue {
    // Validate UTF-8
    if (!std.unicode.utf8ValidateSlice(data)) return error.InvalidUtf8;

    // Return as a JSON string value
    return .{ .string = try arena.dupe(u8, data) };
}

/// Parse a vote instruction into a JSON Value.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_vote.rs#L11
fn parseVoteInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(
        arena,
        sig.runtime.program.vote.Instruction,
        instruction.data,
        .{},
    ) catch {
        return error.DeserializationFailed;
    };
    for (instruction.accounts) |acc_idx| {
        // Runtime should prevent this from ever happening
        if (acc_idx >= account_keys.len()) return error.InstructionKeyMismatch;
    }

    var result = ObjectMap.init(arena);

    switch (ix) {
        .initialize_account => |init_acct| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("node", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("authorizedVoter", try pubkeyToValue(
                arena,
                init_acct.authorized_voter,
            ));
            try info.put("authorizedWithdrawer", try pubkeyToValue(
                arena,
                init_acct.authorized_withdrawer,
            ));
            try info.put("commission", .{ .integer = @intCast(init_acct.commission) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initialize" });
        },
        .authorize => |auth| {
            try checkNumVoteAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(arena, auth.new_authority));
            try info.put("authorityType", voteAuthorizeToValue(auth.vote_authorize));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorize" });
        },
        .authorize_with_seed => |aws| {
            try checkNumVoteAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("authorityBaseKey", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityOwner", try pubkeyToValue(
                arena,
                aws.current_authority_derived_key_owner,
            ));
            try info.put("authoritySeed", .{ .string = aws.current_authority_derived_key_seed });
            try info.put("authorityType", voteAuthorizeToValue(aws.authorization_type));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(arena, aws.new_authority));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeWithSeed" });
        },
        .authorize_checked_with_seed => |acws| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("authorityBaseKey", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityOwner", try pubkeyToValue(
                arena,
                acws.current_authority_derived_key_owner,
            ));
            try info.put("authoritySeed", .{ .string = acws.current_authority_derived_key_seed });
            try info.put("authorityType", voteAuthorizeToValue(acws.authorization_type));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeCheckedWithSeed" });
        },
        .vote => |v| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("slotHashesSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("vote", try voteToValue(arena, v.vote));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "vote" });
        },
        .update_vote_state => |vsu| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteStateUpdate", try voteStateUpdateToValue(
                arena,
                vsu.vote_state_update,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updatevotestate" });
        },
        .update_vote_state_switch => |vsus| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("hash", try hashToValue(arena, vsus.hash));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteStateUpdate", try voteStateUpdateToValue(
                arena,
                vsus.vote_state_update,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updatevotestateswitch" });
        },
        .compact_update_vote_state => |cvsu| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteStateUpdate", try voteStateUpdateToValue(
                arena,
                cvsu.vote_state_update,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "compactupdatevotestate" });
        },
        .compact_update_vote_state_switch => |cvsus| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("hash", try hashToValue(arena, cvsus.hash));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteStateUpdate", try voteStateUpdateToValue(
                arena,
                cvsus.vote_state_update,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "compactupdatevotestateswitch" });
        },
        .tower_sync => |ts| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("towerSync", try towerSyncToValue(arena, ts.tower_sync));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "towersync" });
        },
        .tower_sync_switch => |tss| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("hash", try hashToValue(arena, tss.hash));
            try info.put("towerSync", try towerSyncToValue(arena, tss.tower_sync));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "towersyncswitch" });
        },
        .withdraw => |lamports| {
            try checkNumVoteAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("withdrawAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdraw" });
        },
        .update_validator_identity => {
            try checkNumVoteAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("newValidatorIdentity", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("withdrawAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateValidatorIdentity" });
        },
        .update_commission => |commission| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("commission", .{ .integer = @intCast(commission) });
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("withdrawAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateCommission" });
        },
        .vote_switch => |vs| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("hash", try hashToValue(arena, vs.hash));
            try info.put("slotHashesSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("vote", try voteToValue(arena, vs.vote));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "voteSwitch" });
        },
        .authorize_checked => |auth_type| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityType", voteAuthorizeToValue(auth_type));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeChecked" });
        },
        // TODO: .initializeAccount2
        // TODO: .updateCommissionCollector
        // TODO: .updateComissionBps
    }

    return .{ .object = result };
}

fn checkNumVoteAccounts(accounts: []const u8, num: usize) !void {
    return checkNumAccounts(accounts, num, ParsableProgram.vote);
}

/// Convert a Pubkey to a JSON string value
fn pubkeyToValue(arena: Allocator, pubkey: Pubkey) !JsonValue {
    return .{ .string = try arena.dupe(u8, pubkey.base58String().constSlice()) };
}

/// Convert a Hash to a JSON string value
fn hashToValue(arena: Allocator, hash: Hash) !JsonValue {
    return .{ .string = try arena.dupe(u8, hash.base58String().constSlice()) };
}

/// Convert VoteAuthorize to a JSON string value
fn voteAuthorizeToValue(auth: sig.runtime.program.vote.vote_instruction.VoteAuthorize) JsonValue {
    return .{ .string = switch (auth) {
        .voter => "Voter",
        .withdrawer => "Withdrawer",
    } };
}

/// Convert a Vote to a JSON Value object
fn voteToValue(arena: Allocator, vote: sig.runtime.program.vote.state.Vote) !JsonValue {
    var obj = ObjectMap.init(arena);

    try obj.put("hash", try hashToValue(arena, vote.hash));

    var slots_array = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(
        arena,
        vote.slots.len,
    );
    for (vote.slots) |slot| {
        try slots_array.append(.{ .integer = @intCast(slot) });
    }
    try obj.put("slots", .{ .array = slots_array });

    try obj.put("timestamp", if (vote.timestamp) |ts| .{ .integer = ts } else .null);

    return .{ .object = obj };
}

/// Convert a VoteStateUpdate to a JSON Value object
fn voteStateUpdateToValue(
    arena: Allocator,
    vsu: sig.runtime.program.vote.state.VoteStateUpdate,
) !JsonValue {
    var obj = ObjectMap.init(arena);

    try obj.put("hash", try hashToValue(arena, vsu.hash));
    try obj.put("lockouts", try lockoutsToValue(arena, vsu.lockouts.items));
    try obj.put("root", if (vsu.root) |root| .{ .integer = @intCast(root) } else .null);
    try obj.put("timestamp", if (vsu.timestamp) |ts| .{ .integer = ts } else .null);

    return .{ .object = obj };
}

/// Convert a TowerSync to a JSON Value object
fn towerSyncToValue(
    arena: Allocator,
    ts: sig.runtime.program.vote.state.TowerSync,
) !JsonValue {
    var obj = ObjectMap.init(arena);

    try obj.put("blockId", try hashToValue(arena, ts.block_id));
    try obj.put("hash", try hashToValue(arena, ts.hash));
    try obj.put("lockouts", try lockoutsToValue(arena, ts.lockouts.items));
    try obj.put("root", if (ts.root) |root| .{ .integer = @intCast(root) } else .null);
    try obj.put("timestamp", if (ts.timestamp) |timestamp| .{ .integer = timestamp } else .null);

    return .{ .object = obj };
}

/// Convert an array of Lockouts to a JSON array value
fn lockoutsToValue(
    arena: Allocator,
    lockouts: []const sig.runtime.program.vote.state.Lockout,
) !JsonValue {
    var arr = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(
        arena,
        lockouts.len,
    );

    for (lockouts) |lockout| {
        var lockout_obj = ObjectMap.init(arena);
        try lockout_obj.put(
            "confirmation_count",
            .{ .integer = @intCast(lockout.confirmation_count) },
        );
        try lockout_obj.put("slot", .{ .integer = @intCast(lockout.slot) });
        try arr.append(.{ .object = lockout_obj });
    }

    return .{ .array = arr };
}

/// Parse a system instruction into a JSON Value.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_system.rs#L11
fn parseSystemInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(
        arena,
        SystemInstruction,
        instruction.data,
        .{},
    ) catch {
        return error.DeserializationFailed;
    };
    for (instruction.accounts) |acc_idx| {
        // Runtime should prevent this from ever happening
        if (acc_idx >= account_keys.len()) return error.InstructionKeyMismatch;
    }

    var result = ObjectMap.init(arena);

    switch (ix) {
        .create_account => |ca| {
            try checkNumSystemAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("lamports", .{ .integer = @intCast(ca.lamports) });
            try info.put("newAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(arena, ca.owner));
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("space", .{ .integer = @intCast(ca.space) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createAccount" });
        },
        .assign => |a| {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("owner", try pubkeyToValue(arena, a.owner));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "assign" });
        },
        .transfer => |t| {
            try checkNumSystemAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(t.lamports) });
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "transfer" });
        },
        .create_account_with_seed => |cas| {
            try checkNumSystemAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("base", try pubkeyToValue(arena, cas.base));
            try info.put("lamports", .{ .integer = @intCast(cas.lamports) });
            try info.put("newAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(arena, cas.owner));
            try info.put("seed", .{ .string = cas.seed });
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("space", .{ .integer = @intCast(cas.space) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createAccountWithSeed" });
        },
        .advance_nonce_account => {
            try checkNumSystemAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("nonceAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nonceAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("recentBlockhashesSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "advanceNonce" });
        },
        .withdraw_nonce_account => |lamports| {
            try checkNumSystemAccounts(instruction.accounts, 5);
            var info = ObjectMap.init(arena);
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("nonceAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nonceAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("recentBlockhashesSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdrawFromNonce" });
        },
        .initialize_nonce_account => |authority| {
            try checkNumSystemAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("nonceAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nonceAuthority", try pubkeyToValue(arena, authority));
            try info.put("recentBlockhashesSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeNonce" });
        },
        .authorize_nonce_account => |new_authority| {
            try checkNumSystemAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("newAuthorized", try pubkeyToValue(arena, new_authority));
            try info.put("nonceAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nonceAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeNonce" });
        },
        .allocate => |a| {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("space", .{ .integer = @intCast(a.space) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "allocate" });
        },
        .allocate_with_seed => |aws| {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("base", try pubkeyToValue(arena, aws.base));
            try info.put("owner", try pubkeyToValue(arena, aws.owner));
            try info.put("seed", .{ .string = aws.seed });
            try info.put("space", .{ .integer = @intCast(aws.space) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "allocateWithSeed" });
        },
        .assign_with_seed => |aws| {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("base", try pubkeyToValue(arena, aws.base));
            try info.put("owner", try pubkeyToValue(arena, aws.owner));
            try info.put("seed", .{ .string = aws.seed });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "assignWithSeed" });
        },
        .transfer_with_seed => |tws| {
            try checkNumSystemAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(tws.lamports) });
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("sourceBase", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("sourceOwner", try pubkeyToValue(arena, tws.from_owner));
            try info.put("sourceSeed", .{ .string = tws.from_seed });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "transferWithSeed" });
        },
        .upgrade_nonce_account => {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("nonceAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "upgradeNonce" });
        },
    }

    return .{ .object = result };
}

fn checkNumSystemAccounts(accounts: []const u8, num: usize) !void {
    return checkNumAccounts(accounts, num, ParsableProgram.system);
}

/// Parse an address lookup table instruction into a JSON Value.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_address_lookup_table.rs#L11
fn parseAddressLookupTableInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(
        arena,
        AddressLookupTableInstruction,
        instruction.data,
        .{},
    ) catch {
        return error.DeserializationFailed;
    };

    for (instruction.accounts) |acc_idx| {
        // Runtime should prevent this from ever happening
        if (acc_idx >= account_keys.len()) return error.InstructionKeyMismatch;
    }

    var result = ObjectMap.init(arena);

    switch (ix) {
        .CreateLookupTable => |create| {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("bumpSeed", .{ .integer = @intCast(create.bump_seed) });
            try info.put("lookupTableAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("payerAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("recentSlot", .{ .integer = @intCast(create.recent_slot) });
            try info.put("systemProgram", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createLookupTable" });
        },
        .FreezeLookupTable => {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("lookupTableAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "freezeLookupTable" });
        },
        .ExtendLookupTable => |extend| {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("lookupTableAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Build newAddresses array
            var new_addresses_array = try std.array_list.AlignedManaged(
                JsonValue,
                null,
            ).initCapacity(
                arena,
                extend.new_addresses.len,
            );
            for (extend.new_addresses) |addr| {
                try new_addresses_array.append(try pubkeyToValue(arena, addr));
            }
            try info.put("newAddresses", .{ .array = new_addresses_array });
            // Optional payer and system program (only if >= 4 accounts)
            if (instruction.accounts.len >= 4) {
                try info.put("payerAccount", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[2])).?,
                ));
                try info.put("systemProgram", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[3])).?,
                ));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "extendLookupTable" });
        },
        .DeactivateLookupTable => {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("lookupTableAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "deactivateLookupTable" });
        },
        .CloseLookupTable => {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("lookupTableAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("recipient", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "closeLookupTable" });
        },
    }

    return .{ .object = result };
}

/// Parse a stake instruction into a JSON Value.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_stake.rs#L11
fn parseStakeInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(arena, StakeInstruction, instruction.data, .{}) catch {
        return error.DeserializationFailed;
    };

    var result = ObjectMap.init(arena);

    switch (ix) {
        .initialize => |init| {
            try checkNumStakeAccounts(instruction.accounts, 2);
            const authorized, const lockup = init;
            var info = ObjectMap.init(arena);
            // authorized object
            var authorized_obj = ObjectMap.init(arena);
            try authorized_obj.put("staker", try pubkeyToValue(arena, authorized.staker));
            try authorized_obj.put("withdrawer", try pubkeyToValue(
                arena,
                authorized.withdrawer,
            ));
            try info.put("authorized", .{ .object = authorized_obj });
            // lockup object
            var lockup_obj = ObjectMap.init(arena);
            try lockup_obj.put("custodian", try pubkeyToValue(arena, lockup.custodian));
            try lockup_obj.put("epoch", .{ .integer = @intCast(lockup.epoch) });
            try lockup_obj.put("unixTimestamp", .{ .integer = lockup.unix_timestamp });
            try info.put("lockup", .{ .object = lockup_obj });
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initialize" });
        },
        .authorize => |auth| {
            try checkNumStakeAccounts(instruction.accounts, 3);
            const new_authorized, const authority_type = auth;
            var info = ObjectMap.init(arena);
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityType", stakeAuthorizeToValue(authority_type));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Optional custodian
            if (instruction.accounts.len >= 4) {
                try info.put("custodian", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[3])).?,
                ));
            }
            try info.put("newAuthority", try pubkeyToValue(arena, new_authorized));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorize" });
        },
        .delegate_stake => {
            try checkNumStakeAccounts(instruction.accounts, 6);
            var info = ObjectMap.init(arena);
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try info.put("stakeConfigAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("stakeHistorySysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "delegate" });
        },
        .split => |lamports| {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("newSplitAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "split" });
        },
        .withdraw => |lamports| {
            try checkNumStakeAccounts(instruction.accounts, 5);
            var info = ObjectMap.init(arena);
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            // Optional custodian
            if (instruction.accounts.len >= 6) {
                try info.put("custodian", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[5])).?,
                ));
            }
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeHistorySysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("withdrawAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdraw" });
        },
        .deactivate => {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "deactivate" });
        },
        .set_lockup => |lockup_args| {
            try checkNumStakeAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("custodian", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lockup", try lockupArgsToValue(arena, lockup_args));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "setLockup" });
        },
        .merge => {
            try checkNumStakeAccounts(instruction.accounts, 5);
            var info = ObjectMap.init(arena);
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("stakeHistorySysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "merge" });
        },
        .authorize_with_seed => |aws| {
            try checkNumStakeAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("authorityBase", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authorityOwner", try pubkeyToValue(arena, aws.authority_owner));
            try info.put("authoritySeed", .{ .string = aws.authority_seed });
            try info.put("authorityType", stakeAuthorizeToValue(aws.stake_authorize));
            // Optional clockSysvar
            if (instruction.accounts.len >= 3) {
                try info.put("clockSysvar", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[2])).?,
                ));
            }
            // Optional custodian
            if (instruction.accounts.len >= 4) {
                try info.put("custodian", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[3])).?,
                ));
            }
            try info.put("newAuthorized", try pubkeyToValue(arena, aws.new_authorized_pubkey));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeWithSeed" });
        },
        .initialize_checked => {
            try checkNumStakeAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("staker", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("withdrawer", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeChecked" });
        },
        .authorize_checked => |authority_type| {
            try checkNumStakeAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityType", stakeAuthorizeToValue(authority_type));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Optional custodian
            if (instruction.accounts.len >= 5) {
                try info.put("custodian", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[4])).?,
                ));
            }
            try info.put("newAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeChecked" });
        },
        .authorize_checked_with_seed => |acws| {
            try checkNumStakeAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("authorityBase", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authorityOwner", try pubkeyToValue(arena, acws.authority_owner));
            try info.put("authoritySeed", .{ .string = acws.authority_seed });
            try info.put("authorityType", stakeAuthorizeToValue(acws.stake_authorize));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            // Optional custodian
            if (instruction.accounts.len >= 5) {
                try info.put("custodian", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[4])).?,
                ));
            }
            try info.put("newAuthorized", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeCheckedWithSeed" });
        },
        .set_lockup_checked => |lockup_args| {
            try checkNumStakeAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("custodian", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            var lockup_obj = ObjectMap.init(arena);
            if (lockup_args.epoch) |epoch| {
                try lockup_obj.put("epoch", .{ .integer = @intCast(epoch) });
            }
            if (lockup_args.unix_timestamp) |ts| {
                try lockup_obj.put("unixTimestamp", .{ .integer = ts });
            }
            // Optional new custodian from account
            if (instruction.accounts.len >= 3) {
                try lockup_obj.put("custodian", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[2])).?,
                ));
            }
            try info.put("lockup", .{ .object = lockup_obj });
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "setLockupChecked" });
        },
        .get_minimum_delegation => {
            const info = ObjectMap.init(arena);
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "getMinimumDelegation" });
        },
        .deactivate_delinquent => {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("referenceVoteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "deactivateDelinquent" });
        },
        ._redelegate => {
            try checkNumStakeAccounts(instruction.accounts, 5);
            var info = ObjectMap.init(arena);
            try info.put("newStakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("stakeConfigAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "redelegate" });
        },
        .move_stake => |lamports| {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "moveStake" });
        },
        .move_lamports => |lamports| {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "moveLamports" });
        },
    }

    return .{ .object = result };
}

fn checkNumStakeAccounts(accounts: []const u8, num: usize) !void {
    return checkNumAccounts(accounts, num, ParsableProgram.stake);
}

/// Convert StakeAuthorize to a JSON string value
fn stakeAuthorizeToValue(auth: StakeAuthorize) JsonValue {
    return .{ .string = switch (auth) {
        .staker => "Staker",
        .withdrawer => "Withdrawer",
    } };
}

/// Convert LockupArgs to a JSON Value object
fn lockupArgsToValue(arena: Allocator, lockup_args: StakeLockupArgs) !JsonValue {
    var obj = ObjectMap.init(arena);

    if (lockup_args.custodian) |custodian| {
        try obj.put("custodian", try pubkeyToValue(arena, custodian));
    }
    if (lockup_args.epoch) |epoch| {
        try obj.put("epoch", .{ .integer = @intCast(epoch) });
    }
    if (lockup_args.unix_timestamp) |ts| {
        try obj.put("unixTimestamp", .{ .integer = ts });
    }

    return .{ .object = obj };
}

/// Parse a BPF upgradeable loader instruction into a JSON Value.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_bpf_loader.rs#L48
fn parseBpfUpgradeableLoaderInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(
        arena,
        BpfUpgradeableLoaderInstruction,
        instruction.data,
        .{},
    ) catch {
        return error.DeserializationFailed;
    };

    var result = ObjectMap.init(arena);

    switch (ix) {
        .initialize_buffer => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            // Optional authority
            if (instruction.accounts.len > 1) {
                try info.put("authority", try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(instruction.accounts[1])).?,
                ));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeBuffer" });
        },
        .write => |w| {
            try checkNumBpfLoaderAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Base64 encode the bytes
            const base64_encoder = std.base64.standard;
            const encoded_len = base64_encoder.Encoder.calcSize(w.bytes.len);
            const encoded = try arena.alloc(u8, encoded_len);
            _ = base64_encoder.Encoder.encode(encoded, w.bytes);
            try info.put("bytes", .{ .string = encoded });
            try info.put("offset", .{ .integer = @intCast(w.offset) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "write" });
        },
        .deploy_with_max_data_len => |deploy| {
            try checkNumBpfLoaderAccounts(instruction.accounts, 8);
            var info = ObjectMap.init(arena);
            try info.put("maxDataLen", .{ .integer = @intCast(deploy.max_data_len) });
            try info.put("payerAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programDataAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("bufferAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[6])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[7])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "deployWithMaxDataLen" });
        },
        .upgrade => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 7);
            var info = ObjectMap.init(arena);
            try info.put("programDataAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("bufferAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("spillAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[6])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "upgrade" });
        },
        .set_authority => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Optional new authority
            if (instruction.accounts.len > 2) {
                if (account_keys.get(@intCast(instruction.accounts[2]))) |new_auth| {
                    try info.put("newAuthority", try pubkeyToValue(arena, new_auth));
                } else {
                    try info.put("newAuthority", .null);
                }
            } else {
                try info.put("newAuthority", .null);
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "setAuthority" });
        },
        .set_authority_checked => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "setAuthorityChecked" });
        },
        .close => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("recipient", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            // Optional program account
            if (instruction.accounts.len > 3) {
                if (account_keys.get(@intCast(instruction.accounts[3]))) |prog| {
                    try info.put("programAccount", try pubkeyToValue(arena, prog));
                } else {
                    try info.put("programAccount", .null);
                }
            } else {
                try info.put("programAccount", .null);
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "close" });
        },
        .extend_program => |ext| {
            try checkNumBpfLoaderAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("additionalBytes", .{ .integer = @intCast(ext.additional_bytes) });
            try info.put("programDataAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Optional system program
            if (instruction.accounts.len > 2) {
                if (account_keys.get(@intCast(instruction.accounts[2]))) |sys| {
                    try info.put("systemProgram", try pubkeyToValue(arena, sys));
                } else {
                    try info.put("systemProgram", .null);
                }
            } else {
                try info.put("systemProgram", .null);
            }
            // Optional payer
            if (instruction.accounts.len > 3) {
                if (account_keys.get(@intCast(instruction.accounts[3]))) |payer| {
                    try info.put("payerAccount", try pubkeyToValue(arena, payer));
                } else {
                    try info.put("payerAccount", .null);
                }
            } else {
                try info.put("payerAccount", .null);
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "extendProgram" });
        },
        .migrate => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("programDataAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "migrate" });
        },
        .extend_program_checked => |ext| {
            try checkNumBpfLoaderAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("additionalBytes", .{ .integer = @intCast(ext.additional_bytes) });
            try info.put("programDataAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            // Optional system program
            if (instruction.accounts.len > 3) {
                if (account_keys.get(@intCast(instruction.accounts[3]))) |sys| {
                    try info.put("systemProgram", try pubkeyToValue(arena, sys));
                } else {
                    try info.put("systemProgram", .null);
                }
            } else {
                try info.put("systemProgram", .null);
            }
            // Optional payer
            if (instruction.accounts.len > 4) {
                if (account_keys.get(@intCast(instruction.accounts[4]))) |payer| {
                    try info.put("payerAccount", try pubkeyToValue(arena, payer));
                } else {
                    try info.put("payerAccount", .null);
                }
            } else {
                try info.put("payerAccount", .null);
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "extendProgramChecked" });
        },
    }

    return .{ .object = result };
}

fn checkNumBpfLoaderAccounts(
    accounts: []const u8,
    num: usize,
) !void {
    return checkNumAccounts(accounts, num, ParsableProgram.bpfLoader);
}

fn checkNumBpfUpgradeableLoaderAccounts(
    accounts: []const u8,
    num: usize,
) !void {
    return checkNumAccounts(accounts, num, ParsableProgram.bpfUpgradeableLoader);
}

fn checkNumAddressLookupTableAccounts(
    accounts: []const u8,
    num: usize,
) !void {
    return checkNumAccounts(accounts, num, .addressLookupTable);
}

fn checkNumAccounts(
    accounts: []const u8,
    num: usize,
    parsable_program: ParsableProgram,
) !void {
    if (accounts.len < num) {
        return switch (parsable_program) {
            .addressLookupTable => error.NotEnoughAddressLookupTableAccounts,
            .splAssociatedTokenAccount => error.NotEnoughSplAssociatedTokenAccountAccounts,
            .splMemo => error.NotEnoughSplMemoAccounts,
            .splToken => error.NotEnoughSplTokenAccounts,
            .bpfLoader => error.NotEnoughBpfLoaderAccounts,
            .bpfUpgradeableLoader => error.NotEnoughBpfUpgradeableLoaderAccounts,
            .stake => error.NotEnoughStakeAccounts,
            .system => error.NotEnoughSystemAccounts,
            .vote => error.NotEnoughVoteAccounts,
        };
    }
}

/// Parse a BPF Loader v2 instruction into a JSON Value.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_bpf_loader.rs#L13
fn parseBpfLoaderInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(
        arena,
        BpfLoaderInstruction,
        instruction.data,
        .{},
    ) catch {
        return error.DeserializationFailed;
    };

    // Validate account keys
    if (instruction.accounts.len == 0 or instruction.accounts[0] >= account_keys.len()) {
        return error.InstructionKeyMismatch;
    }

    var result = ObjectMap.init(arena);

    switch (ix) {
        .write => |w| {
            try checkNumBpfLoaderAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("offset", .{ .integer = @intCast(w.offset) });
            // Base64 encode the bytes
            const base64_encoder = std.base64.standard;
            const encoded_len = base64_encoder.Encoder.calcSize(w.bytes.len);
            const encoded = try arena.alloc(u8, encoded_len);
            _ = base64_encoder.Encoder.encode(encoded, w.bytes);
            try info.put("bytes", .{ .string = encoded });
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "write" });
        },
        .finalize => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "finalize" });
        },
    }

    return .{ .object = result };
}

/// Parse an Associated Token Account instruction into a JSON Value.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_associated_token.rs#L11
fn parseAssociatedTokenInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    // Validate account indices don't exceed account_keys length
    for (instruction.accounts) |acc_idx| {
        if (acc_idx >= account_keys.len()) {
            return error.InstructionKeyMismatch;
        }
    }

    // Parse instruction - empty data means Create, otherwise try borsh deserialize
    const ata_instruction: AssociatedTokenAccountInstruction = if (instruction.data.len == 0)
        .create
    else blk: {
        if (instruction.data.len < 1) return error.DeserializationFailed;
        break :blk std.meta.intToEnum(AssociatedTokenAccountInstruction, instruction.data[0]) catch {
            return error.DeserializationFailed;
        };
    };

    var result = ObjectMap.init(arena);

    switch (ata_instruction) {
        .create => {
            try checkNumAssociatedTokenAccounts(instruction.accounts, 6);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("wallet", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("tokenProgram", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "create" });
        },
        .create_idempotent => {
            try checkNumAssociatedTokenAccounts(instruction.accounts, 6);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("wallet", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("tokenProgram", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createIdempotent" });
        },
        .recover_nested => {
            try checkNumAssociatedTokenAccounts(instruction.accounts, 7);
            var info = ObjectMap.init(arena);
            try info.put("nestedSource", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nestedMint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("nestedOwner", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("ownerMint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("wallet", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try info.put("tokenProgram", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[6])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "recoverNested" });
        },
    }

    return .{ .object = result };
}

fn checkNumAssociatedTokenAccounts(accounts: []const u8, num: usize) !void {
    return checkNumAccounts(accounts, num, .splAssociatedTokenAccount);
}

/// SPL Token instruction tag (first byte)
/// [agave] https://github.com/solana-program/token/blob/f403c97ed4522469c2e320b8b4a2941f24c40a5e/interface/src/instruction.rs#L478
const TokenInstructionTag = enum(u8) {
    initializeMint = 0,
    initializeAccount = 1,
    initializeMultisig = 2,
    transfer = 3,
    approve = 4,
    revoke = 5,
    setAuthority = 6,
    mintTo = 7,
    burn = 8,
    closeAccount = 9,
    freezeAccount = 10,
    thawAccount = 11,
    transferChecked = 12,
    approveChecked = 13,
    mintToChecked = 14,
    burnChecked = 15,
    initializeAccount2 = 16,
    syncNative = 17,
    initializeAccount3 = 18,
    initializeMultisig2 = 19,
    initializeMint2 = 20,
    getAccountDataSize = 21,
    initializeImmutableOwner = 22,
    amountToUiAmount = 23,
    uiAmountToAmount = 24,
    initializeMintCloseAuthority = 25,
    // Extensions start at higher values
    transferFeeExtension = 26,
    confidentialTransferExtension = 27,
    defaultAccountStateExtension = 28,
    reallocate = 29,
    memoTransferExtension = 30,
    createNativeMint = 31,
    initializeNonTransferableMint = 32,
    interestBearingMintExtension = 33,
    cpiGuardExtension = 34,
    initializePermanentDelegate = 35,
    transferHookExtension = 36,
    confidentialTransferFeeExtension = 37,
    withdrawExcessLamports = 38,
    metadataPointerExtension = 39,
    groupPointerExtension = 40,
    groupMemberPointerExtension = 41,
    confidentialMintBurnExtension = 42,
    scaledUiAmountExtension = 43,
    pausableExtension = 44,
};

/// Authority type for SetAuthority instruction
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token.rs#L730
const TokenAuthorityType = enum(u8) {
    mintTokens = 0,
    freezeAccount = 1,
    accountOwner = 2,
    closeAccount = 3,
    transferFeeConfig = 4,
    withheldWithdraw = 5,
    closeMint = 6,
    interestRate = 7,
    permanentDelegate = 8,
    confidentialTransferMint = 9,
    transferHookProgramId = 10,
    confidentialTransferFeeConfig = 11,
    metadataPointer = 12,
    groupPointer = 13,
    groupMemberPointer = 14,
    scaledUiAmount = 15,
    pause = 16,
};

/// Parse an SPL Token instruction into a JSON Value.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token.rs#L30
fn parseTokenInstruction(
    arena: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    // Validate account indices don't exceed account_keys length
    for (instruction.accounts) |acc_idx| {
        if (acc_idx >= account_keys.len()) {
            return error.InstructionKeyMismatch;
        }
    }

    if (instruction.data.len == 0) {
        return error.DeserializationFailed;
    }

    const tag = std.meta.intToEnum(TokenInstructionTag, instruction.data[0]) catch {
        return error.DeserializationFailed;
    };

    var result = ObjectMap.init(arena);

    switch (tag) {
        .initializeMint => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            if (instruction.data.len < 35) return error.DeserializationFailed;
            const decimals = instruction.data[1];
            const mint_authority = Pubkey{ .data = instruction.data[2..34].* };
            // freeze_authority is optional: 1 byte tag + 32 bytes pubkey
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("decimals", .{ .integer = @intCast(decimals) });
            try info.put("mintAuthority", try pubkeyToValue(arena, mint_authority));
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            if (instruction.data.len >= 67 and instruction.data[34] == 1) {
                const freeze_authority = Pubkey{ .data = instruction.data[35..67].* };
                try info.put("freezeAuthority", try pubkeyToValue(arena, freeze_authority));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMint" });
        },
        .initializeMint2 => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            if (instruction.data.len < 35) return error.DeserializationFailed;
            const decimals = instruction.data[1];
            const mint_authority = Pubkey{ .data = instruction.data[2..34].* };
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("decimals", .{ .integer = @intCast(decimals) });
            try info.put("mintAuthority", try pubkeyToValue(arena, mint_authority));
            if (instruction.data.len >= 67 and instruction.data[34] == 1) {
                const freeze_authority = Pubkey{ .data = instruction.data[35..67].* };
                try info.put("freezeAuthority", try pubkeyToValue(arena, freeze_authority));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMint2" });
        },
        .initializeAccount => {
            try checkNumTokenAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeAccount" });
        },
        .initializeAccount2 => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 33) return error.DeserializationFailed;
            const owner = Pubkey{ .data = instruction.data[1..33].* };
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(arena, owner));
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeAccount2" });
        },
        .initializeAccount3 => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            if (instruction.data.len < 33) return error.DeserializationFailed;
            const owner = Pubkey{ .data = instruction.data[1..33].* };
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(arena, owner));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeAccount3" });
        },
        .initializeMultisig => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const m = instruction.data[1];
            var info = ObjectMap.init(arena);
            try info.put("multisig", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            var signers = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(
                arena,
                instruction.accounts[2..].len,
            );
            for (instruction.accounts[2..]) |signer_idx| {
                try signers.append(try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(signer_idx)).?,
                ));
            }
            try info.put("signers", .{ .array = signers });
            try info.put("m", .{ .integer = @intCast(m) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMultisig" });
        },
        .initializeMultisig2 => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const m = instruction.data[1];
            var info = ObjectMap.init(arena);
            try info.put("multisig", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            var signers = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(
                arena,
                instruction.accounts[1..].len,
            );
            for (instruction.accounts[1..]) |signer_idx| {
                try signers.append(try pubkeyToValue(
                    arena,
                    account_keys.get(@intCast(signer_idx)).?,
                ));
            }
            try info.put("signers", .{ .array = signers });
            try info.put("m", .{ .integer = @intCast(m) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMultisig2" });
        },
        .transfer => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                arena,
                "{d}",
                .{amount},
            ) });
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "transfer" });
        },
        .approve => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("delegate", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                arena,
                "{d}",
                .{amount},
            ) });
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "owner",
                "multisigOwner",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "approve" });
        },
        .revoke => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try parseSigners(
                arena,
                &info,
                1,
                account_keys,
                instruction.accounts,
                "owner",
                "multisigOwner",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "revoke" });
        },
        .setAuthority => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            if (instruction.data.len < 3) return error.DeserializationFailed;
            const authority_type = std.meta.intToEnum(
                TokenAuthorityType,
                instruction.data[1],
            ) catch TokenAuthorityType.mintTokens;
            const owned_field = switch (authority_type) {
                .mintTokens,
                .freezeAccount,
                .transferFeeConfig,
                .withheldWithdraw,
                .closeMint,
                .interestRate,
                .permanentDelegate,
                .confidentialTransferMint,
                .transferHookProgramId,
                .confidentialTransferFeeConfig,
                .metadataPointer,
                .groupPointer,
                .groupMemberPointer,
                .scaledUiAmount,
                .pause,
                => "mint",
                .accountOwner, .closeAccount => "account",
            };
            var info = ObjectMap.init(arena);
            try info.put(owned_field, try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("authorityType", .{ .string = @tagName(authority_type) });
            // new_authority: COption<Pubkey> - 1 byte tag + 32 bytes pubkey
            if (instruction.data.len >= 35 and instruction.data[2] == 1) {
                const new_authority = Pubkey{ .data = instruction.data[3..35].* };
                try info.put("newAuthority", try pubkeyToValue(arena, new_authority));
            } else {
                try info.put("newAuthority", .null);
            }
            try parseSigners(
                arena,
                &info,
                1,
                account_keys,
                instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "setAuthority" });
        },
        .mintTo => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                arena,
                "{d}",
                .{amount},
            ) });
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "mintAuthority",
                "multisigMintAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "mintTo" });
        },
        .burn => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                arena,
                "{d}",
                .{amount},
            ) });
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "burn" });
        },
        .closeAccount => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "owner",
                "multisigOwner",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "closeAccount" });
        },
        .freezeAccount => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "freezeAuthority",
                "multisigFreezeAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "freezeAccount" });
        },
        .thawAccount => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "freezeAuthority",
                "multisigFreezeAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "thawAccount" });
        },
        .transferChecked => {
            try checkNumTokenAccounts(instruction.accounts, 4);
            if (instruction.data.len < 10) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            const decimals = instruction.data[9];
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("tokenAmount", try tokenAmountToUiAmount(arena, amount, decimals));
            try parseSigners(
                arena,
                &info,
                3,
                account_keys,
                instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "transferChecked" });
        },
        .approveChecked => {
            try checkNumTokenAccounts(instruction.accounts, 4);
            if (instruction.data.len < 10) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            const decimals = instruction.data[9];
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("delegate", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("tokenAmount", try tokenAmountToUiAmount(arena, amount, decimals));
            try parseSigners(
                arena,
                &info,
                3,
                account_keys,
                instruction.accounts,
                "owner",
                "multisigOwner",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "approveChecked" });
        },
        .mintToChecked => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 10) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            const decimals = instruction.data[9];
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("tokenAmount", try tokenAmountToUiAmount(arena, amount, decimals));
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "mintAuthority",
                "multisigMintAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "mintToChecked" });
        },
        .burnChecked => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 10) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            const decimals = instruction.data[9];
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("tokenAmount", try tokenAmountToUiAmount(arena, amount, decimals));
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "burnChecked" });
        },
        .syncNative => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "syncNative" });
        },
        .getAccountDataSize => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            // Extension types are in remaining data, but we'll skip detailed parsing for now
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "getAccountDataSize" });
        },
        .initializeImmutableOwner => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeImmutableOwner" });
        },
        .amountToUiAmount => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                arena,
                "{d}",
                .{amount},
            ) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "amountToUiAmount" });
        },
        .uiAmountToAmount => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            // ui_amount is a string in remaining bytes
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            if (instruction.data.len > 1) {
                try info.put("uiAmount", .{ .string = instruction.data[1..] });
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "uiAmountToAmount" });
        },
        .initializeMintCloseAuthority => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            // close_authority: COption<Pubkey>
            if (instruction.data.len >= 34 and instruction.data[1] == 1) {
                const close_authority = Pubkey{ .data = instruction.data[2..34].* };
                try info.put("closeAuthority", try pubkeyToValue(arena, close_authority));
            } else {
                try info.put("closeAuthority", .null);
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMintCloseAuthority" });
        },
        .createNativeMint => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("payer", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nativeMint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createNativeMint" });
        },
        .initializeNonTransferableMint => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeNonTransferableMint" });
        },
        .initializePermanentDelegate => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            if (instruction.data.len >= 33) {
                const delegate = Pubkey{ .data = instruction.data[1..33].* };
                try info.put("delegate", try pubkeyToValue(arena, delegate));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializePermanentDelegate" });
        },
        .withdrawExcessLamports => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try parseSigners(
                arena,
                &info,
                2,
                account_keys,
                instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdrawExcessLamports" });
        },
        .reallocate => {
            try checkNumTokenAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("payer", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                arena,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try parseSigners(
                arena,
                &info,
                3,
                account_keys,
                instruction.accounts,
                "owner",
                "multisigOwner",
            );
            // extension_types in remaining data - skip for now
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "reallocate" });
        },
        .transferFeeExtension => {
            const ext_data = instruction.data[1..];
            const sub_result = try parseTransferFeeExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .confidentialTransferExtension => {
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseConfidentialTransferExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .defaultAccountStateExtension => {
            if (instruction.data.len <= 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseDefaultAccountStateExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .memoTransferExtension => {
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseMemoTransferExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .interestBearingMintExtension => {
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseInterestBearingMintExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .cpiGuardExtension => {
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseCpiGuardExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .transferHookExtension => {
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseTransferHookExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .confidentialTransferFeeExtension => {
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseConfidentialTransferFeeExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .metadataPointerExtension => {
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseMetadataPointerExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .groupPointerExtension => {
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseGroupPointerExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .groupMemberPointerExtension => {
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const ext_data = instruction.data[1..];
            const sub_result = try parseGroupMemberPointerExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .confidentialMintBurnExtension => {
            const ext_data = instruction.data[1..];
            const sub_result = try parseConfidentialMintBurnExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .scaledUiAmountExtension => {
            const ext_data = instruction.data[1..];
            const sub_result = try parseScaledUiAmountExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
        .pausableExtension => {
            const ext_data = instruction.data[1..];
            const sub_result = try parsePausableExtension(arena, ext_data, instruction.accounts, account_keys);
            return sub_result;
        },
    }

    return .{ .object = result };
}

fn checkNumTokenAccounts(accounts: []const u8, num: usize) !void {
    return checkNumAccounts(accounts, num, .splToken);
}

/// Helper to read an OptionalNonZeroPubkey (32 bytes, all zeros = None)
fn readOptionalNonZeroPubkey(data: []const u8, offset: usize) ?Pubkey {
    if (data.len < offset + 32) return null;
    const bytes = data[offset..][0..32];
    if (std.mem.eql(u8, bytes, &([_]u8{0} ** 32))) return null;
    return Pubkey{ .data = bytes.* };
}

/// Helper to read a COption<Pubkey>: 4 bytes tag (LE) + 32 bytes pubkey if tag == 1
/// Returns the pubkey if present, null if tag == 0, and the number of bytes consumed.
fn readCOptionPubkey(data: []const u8, offset: usize) !struct { pubkey: ?Pubkey, len: usize } {
    if (data.len < offset + 4) return error.DeserializationFailed;
    const tag = std.mem.readInt(u32, data[offset..][0..4], .little);
    if (tag == 0) {
        return .{ .pubkey = null, .len = 4 };
    } else if (tag == 1) {
        if (data.len < offset + 4 + 32) return error.DeserializationFailed;
        return .{ .pubkey = Pubkey{ .data = data[offset + 4 ..][0..32].* }, .len = 36 };
    } else {
        return error.DeserializationFailed;
    }
}

/// Parse a TransferFee extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/transfer_fee.rs
fn parseTransferFeeExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];
    const data = ext_data[1..];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // InitializeTransferFeeConfig
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            // COption<Pubkey> transfer_fee_config_authority
            const auth1 = try readCOptionPubkey(data, 0);
            if (auth1.pubkey) |pk| {
                try info.put("transferFeeConfigAuthority", try pubkeyToValue(arena, pk));
            }
            // COption<Pubkey> withdraw_withheld_authority
            const auth2 = try readCOptionPubkey(data, auth1.len);
            if (auth2.pubkey) |pk| {
                try info.put("withdrawWithheldAuthority", try pubkeyToValue(arena, pk));
            }
            const fee_offset = auth1.len + auth2.len;
            if (data.len < fee_offset + 10) return error.DeserializationFailed;
            const basis_points = std.mem.readInt(u16, data[fee_offset..][0..2], .little);
            const maximum_fee = std.mem.readInt(u64, data[fee_offset + 2 ..][0..8], .little);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("transferFeeBasisPoints", .{ .integer = @intCast(basis_points) });
            try info.put("maximumFee", .{ .integer = @intCast(maximum_fee) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeTransferFeeConfig" });
        },
        // TransferCheckedWithFee
        1 => {
            try checkNumTokenAccounts(accounts, 4);
            if (data.len < 17) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, data[0..8], .little);
            const decimals = data[8];
            const fee = std.mem.readInt(u64, data[9..17], .little);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try info.put("destination", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[2])).?));
            try info.put("tokenAmount", try tokenAmountToUiAmount(arena, amount, decimals));
            try info.put("feeAmount", try tokenAmountToUiAmount(arena, fee, decimals));
            try parseSigners(arena, &info, 3, account_keys, accounts, "authority", "multisigAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "transferCheckedWithFee" });
        },
        // WithdrawWithheldTokensFromMint
        2 => {
            try checkNumTokenAccounts(accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("feeRecipient", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try parseSigners(arena, &info, 2, account_keys, accounts, "withdrawWithheldAuthority", "multisigWithdrawWithheldAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdrawWithheldTokensFromMint" });
        },
        // WithdrawWithheldTokensFromAccounts
        3 => {
            if (data.len < 1) return error.DeserializationFailed;
            const num_token_accounts = data[0];
            try checkNumTokenAccounts(accounts, 3 + @as(usize, num_token_accounts));
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("feeRecipient", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            // Source accounts are the last num_token_accounts
            const first_source = accounts.len - @as(usize, num_token_accounts);
            var source_accounts = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(arena, num_token_accounts);
            for (accounts[first_source..]) |acc_idx| {
                try source_accounts.append(try pubkeyToValue(arena, account_keys.get(@intCast(acc_idx)).?));
            }
            try info.put("sourceAccounts", .{ .array = source_accounts });
            try parseSigners(arena, &info, 2, account_keys, accounts[0..first_source], "withdrawWithheldAuthority", "multisigWithdrawWithheldAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdrawWithheldTokensFromAccounts" });
        },
        // HarvestWithheldTokensToMint
        4 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            var source_accounts = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(arena, if (accounts.len > 1) accounts.len - 1 else 0);
            for (accounts[1..]) |acc_idx| {
                try source_accounts.append(try pubkeyToValue(arena, account_keys.get(@intCast(acc_idx)).?));
            }
            try info.put("sourceAccounts", .{ .array = source_accounts });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "harvestWithheldTokensToMint" });
        },
        // SetTransferFee
        5 => {
            try checkNumTokenAccounts(accounts, 2);
            if (data.len < 10) return error.DeserializationFailed;
            const basis_points = std.mem.readInt(u16, data[0..2], .little);
            const maximum_fee = std.mem.readInt(u64, data[2..10], .little);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("transferFeeBasisPoints", .{ .integer = @intCast(basis_points) });
            try info.put("maximumFee", .{ .integer = @intCast(maximum_fee) });
            try parseSigners(arena, &info, 1, account_keys, accounts, "transferFeeConfigAuthority", "multisigtransferFeeConfigAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "setTransferFee" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a ConfidentialTransfer extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/confidential_transfer.rs
fn parseConfidentialTransferExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // InitializeMint
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            // Authority is an OptionalNonZeroPubkey (32 bytes)
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("authority", try pubkeyToValue(arena, pk));
                }
            }
            // TODO: parse autoApproveNewAccounts and auditorElGamalPubkey from data
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeConfidentialTransferMint" });
        },
        // UpdateMint
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("confidentialTransferMintAuthority", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateConfidentialTransferMint" });
        },
        // ConfigureAccount
        2 => {
            try checkNumTokenAccounts(accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "configureConfidentialTransferAccount" });
        },
        // ApproveAccount
        3 => {
            try checkNumTokenAccounts(accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try info.put("confidentialTransferAuditorAuthority", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[2])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "approveConfidentialTransferAccount" });
        },
        // EmptyAccount
        4 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "emptyConfidentialTransferAccount" });
        },
        // Deposit
        5 => {
            try checkNumTokenAccounts(accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("destination", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[2])).?));
            // Parse amount and decimals from data if available
            if (ext_data.len >= 10) {
                const amount = std.mem.readInt(u64, ext_data[1..9], .little);
                const decimals = ext_data[9];
                try info.put("amount", .{ .integer = @intCast(amount) });
                try info.put("decimals", .{ .integer = @intCast(decimals) });
            }
            try parseSigners(arena, &info, 3, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "depositConfidentialTransfer" });
        },
        // Withdraw
        6 => {
            try checkNumTokenAccounts(accounts, 4);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("destination", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[2])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdrawConfidentialTransfer" });
        },
        // Transfer
        7 => {
            try checkNumTokenAccounts(accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try info.put("destination", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[2])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "confidentialTransfer" });
        },
        // ApplyPendingBalance
        8 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 0, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "applyPendingConfidentialTransferBalance" });
        },
        // EnableConfidentialCredits
        9 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 0, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "enableConfidentialTransferConfidentialCredits" });
        },
        // DisableConfidentialCredits
        10 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 0, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "disableConfidentialTransferConfidentialCredits" });
        },
        // EnableNonConfidentialCredits
        11 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 0, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "enableConfidentialTransferNonConfidentialCredits" });
        },
        // DisableNonConfidentialCredits
        12 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 0, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "disableConfidentialTransferNonConfidentialCredits" });
        },
        // TransferWithFee
        13 => {
            try checkNumTokenAccounts(accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("source", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try info.put("destination", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[2])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "confidentialTransferWithFee" });
        },
        // ConfigureAccountWithRegistry
        14 => {
            try checkNumTokenAccounts(accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try info.put("registry", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[2])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "configureConfidentialAccountWithRegistry" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a DefaultAccountState extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/default_account_state.rs
fn parseDefaultAccountStateExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 2) return error.DeserializationFailed;
    const sub_tag = ext_data[0];
    // Account state is the byte after the sub-tag
    const account_state_byte = ext_data[1];
    const account_state: []const u8 = switch (account_state_byte) {
        0 => "uninitialized",
        1 => "initialized",
        2 => "frozen",
        else => return error.DeserializationFailed,
    };

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Initialize
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("accountState", .{ .string = account_state });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeDefaultAccountState" });
        },
        // Update
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("accountState", .{ .string = account_state });
            try parseSigners(arena, &info, 1, account_keys, accounts, "freezeAuthority", "multisigFreezeAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateDefaultAccountState" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a MemoTransfer extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/memo_transfer.rs
fn parseMemoTransferExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Enable
        0 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 1, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "enableRequiredMemoTransfers" });
        },
        // Disable
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 1, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "disableRequiredMemoTransfers" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse an InterestBearingMint extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/interest_bearing_mint.rs
fn parseInterestBearingMintExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Initialize { rate_authority: COption<Pubkey>, rate: i16 }
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            // COption<Pubkey> rate_authority followed by i16 rate
            if (ext_data.len >= 1 + 4) {
                const auth = try readCOptionPubkey(ext_data, 1);
                if (auth.pubkey) |pk| {
                    try info.put("rateAuthority", try pubkeyToValue(arena, pk));
                } else {
                    try info.put("rateAuthority", .null);
                }
                const rate_offset = 1 + auth.len;
                if (ext_data.len >= rate_offset + 2) {
                    const rate = std.mem.readInt(i16, ext_data[rate_offset..][0..2], .little);
                    try info.put("rate", .{ .integer = @intCast(rate) });
                }
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeInterestBearingConfig" });
        },
        // UpdateRate { rate: i16 }
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 3) {
                const rate = std.mem.readInt(i16, ext_data[1..3], .little);
                try info.put("newRate", .{ .integer = @intCast(rate) });
            }
            try parseSigners(arena, &info, 1, account_keys, accounts, "rateAuthority", "multisigRateAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateInterestBearingConfigRate" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a CpiGuard extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/cpi_guard.rs
fn parseCpiGuardExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Enable
        0 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 1, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "enableCpiGuard" });
        },
        // Disable
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 1, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "disableCpiGuard" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a TransferHook extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/transfer_hook.rs
fn parseTransferHookExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Initialize { authority: OptionalNonZeroPubkey, program_id: OptionalNonZeroPubkey }
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("authority", try pubkeyToValue(arena, pk));
                }
            }
            if (ext_data.len >= 65) {
                if (readOptionalNonZeroPubkey(ext_data, 33)) |pk| {
                    try info.put("programId", try pubkeyToValue(arena, pk));
                }
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeTransferHook" });
        },
        // Update { program_id: OptionalNonZeroPubkey }
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("programId", try pubkeyToValue(arena, pk));
                }
            }
            try parseSigners(arena, &info, 1, account_keys, accounts, "authority", "multisigAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateTransferHook" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a ConfidentialTransferFee extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/confidential_transfer_fee.rs
fn parseConfidentialTransferFeeExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // InitializeConfidentialTransferFeeConfig
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            // OptionalNonZeroPubkey authority (32 bytes) + PodElGamalPubkey (32 bytes)
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("authority", try pubkeyToValue(arena, pk));
                }
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeConfidentialTransferFeeConfig" });
        },
        // WithdrawWithheldTokensFromMint
        1 => {
            try checkNumTokenAccounts(accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("feeRecipient", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdrawWithheldConfidentialTransferTokensFromMint" });
        },
        // WithdrawWithheldTokensFromAccounts
        2 => {
            try checkNumTokenAccounts(accounts, 3);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("feeRecipient", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdrawWithheldConfidentialTransferTokensFromAccounts" });
        },
        // HarvestWithheldTokensToMint
        3 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            var source_accounts = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(arena, if (accounts.len > 1) accounts.len - 1 else 0);
            for (accounts[1..]) |acc_idx| {
                try source_accounts.append(try pubkeyToValue(arena, account_keys.get(@intCast(acc_idx)).?));
            }
            try info.put("sourceAccounts", .{ .array = source_accounts });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "harvestWithheldConfidentialTransferTokensToMint" });
        },
        // EnableHarvestToMint
        4 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 1, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "enableConfidentialTransferFeeHarvestToMint" });
        },
        // DisableHarvestToMint
        5 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("account", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 1, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "disableConfidentialTransferFeeHarvestToMint" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a MetadataPointer extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/metadata_pointer.rs
fn parseMetadataPointerExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Initialize { authority: OptionalNonZeroPubkey, metadata_address: OptionalNonZeroPubkey }
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("authority", try pubkeyToValue(arena, pk));
                }
            }
            if (ext_data.len >= 65) {
                if (readOptionalNonZeroPubkey(ext_data, 33)) |pk| {
                    try info.put("metadataAddress", try pubkeyToValue(arena, pk));
                }
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMetadataPointer" });
        },
        // Update { metadata_address: OptionalNonZeroPubkey }
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("metadataAddress", try pubkeyToValue(arena, pk));
                }
            }
            try parseSigners(arena, &info, 1, account_keys, accounts, "authority", "multisigAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateMetadataPointer" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a GroupPointer extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/group_pointer.rs
fn parseGroupPointerExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Initialize { authority: OptionalNonZeroPubkey, group_address: OptionalNonZeroPubkey }
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("authority", try pubkeyToValue(arena, pk));
                }
            }
            if (ext_data.len >= 65) {
                if (readOptionalNonZeroPubkey(ext_data, 33)) |pk| {
                    try info.put("groupAddress", try pubkeyToValue(arena, pk));
                }
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeGroupPointer" });
        },
        // Update { group_address: OptionalNonZeroPubkey }
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("groupAddress", try pubkeyToValue(arena, pk));
                }
            }
            try parseSigners(arena, &info, 1, account_keys, accounts, "authority", "multisigAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateGroupPointer" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a GroupMemberPointer extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/group_member_pointer.rs
fn parseGroupMemberPointerExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Initialize { authority: OptionalNonZeroPubkey, member_address: OptionalNonZeroPubkey }
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("authority", try pubkeyToValue(arena, pk));
                }
            }
            if (ext_data.len >= 65) {
                if (readOptionalNonZeroPubkey(ext_data, 33)) |pk| {
                    try info.put("memberAddress", try pubkeyToValue(arena, pk));
                }
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeGroupMemberPointer" });
        },
        // Update { member_address: OptionalNonZeroPubkey }
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("memberAddress", try pubkeyToValue(arena, pk));
                }
            }
            try parseSigners(arena, &info, 1, account_keys, accounts, "authority", "multisigAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateGroupMemberPointer" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a ConfidentialMintBurn extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/confidential_mint_burn.rs
fn parseConfidentialMintBurnExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // InitializeMint
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeConfidentialMintBurnMint" });
        },
        // RotateSupplyElGamalPubkey
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "rotateConfidentialMintBurnSupplyElGamalPubkey" });
        },
        // UpdateDecryptableSupply
        2 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 0, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateConfidentialMintBurnDecryptableSupply" });
        },
        // Mint
        3 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("destination", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "confidentialMint" });
        },
        // Burn
        4 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("destination", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[1])).?));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "confidentialBurn" });
        },
        // ApplyPendingBurn
        5 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 0, account_keys, accounts, "owner", "multisigOwner");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "applyPendingBurn" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a ScaledUiAmount extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/scaled_ui_amount.rs
fn parseScaledUiAmountExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Initialize { authority: OptionalNonZeroPubkey, multiplier: f64 }
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("authority", try pubkeyToValue(arena, pk));
                } else {
                    try info.put("authority", .null);
                }
            }
            if (ext_data.len >= 41) {
                const multiplier_bytes = ext_data[33..41];
                const multiplier: f64 = @bitCast(std.mem.readInt(u64, multiplier_bytes[0..8], .little));
                try info.put("multiplier", .{ .string = try std.fmt.allocPrint(arena, "{d}", .{multiplier}) });
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeScaledUiAmountConfig" });
        },
        // UpdateMultiplier { multiplier: f64, effective_timestamp: i64 }
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 9) {
                const multiplier: f64 = @bitCast(std.mem.readInt(u64, ext_data[1..9], .little));
                try info.put("newMultiplier", .{ .string = try std.fmt.allocPrint(arena, "{d}", .{multiplier}) });
            }
            if (ext_data.len >= 17) {
                const timestamp = std.mem.readInt(i64, ext_data[9..17], .little);
                try info.put("newMultiplierTimestamp", .{ .integer = timestamp });
            }
            try parseSigners(arena, &info, 1, account_keys, accounts, "authority", "multisigAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateMultiplier" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse a Pausable extension sub-instruction.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token/extension/pausable.rs
fn parsePausableExtension(
    arena: Allocator,
    ext_data: []const u8,
    accounts: []const u8,
    account_keys: *const AccountKeys,
) !JsonValue {
    if (ext_data.len < 1) return error.DeserializationFailed;
    const sub_tag = ext_data[0];

    var result = ObjectMap.init(arena);

    switch (sub_tag) {
        // Initialize { authority: OptionalNonZeroPubkey }
        0 => {
            try checkNumTokenAccounts(accounts, 1);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            if (ext_data.len >= 33) {
                if (readOptionalNonZeroPubkey(ext_data, 1)) |pk| {
                    try info.put("authority", try pubkeyToValue(arena, pk));
                } else {
                    try info.put("authority", .null);
                }
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializePausableConfig" });
        },
        // Pause
        1 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 1, account_keys, accounts, "authority", "multisigAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "pause" });
        },
        // Resume
        2 => {
            try checkNumTokenAccounts(accounts, 2);
            var info = ObjectMap.init(arena);
            try info.put("mint", try pubkeyToValue(arena, account_keys.get(@intCast(accounts[0])).?));
            try parseSigners(arena, &info, 1, account_keys, accounts, "authority", "multisigAuthority");
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "resume" });
        },
        else => return error.DeserializationFailed,
    }

    return .{ .object = result };
}

/// Parse signers for SPL Token instructions.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_token.rs#L850
fn parseSigners(
    arena: Allocator,
    info: *ObjectMap,
    last_nonsigner_index: usize,
    account_keys: *const AccountKeys,
    accounts: []const u8,
    owner_field_name: []const u8,
    multisig_field_name: []const u8,
) !void {
    if (accounts.len > last_nonsigner_index + 1) {
        // Multisig case
        var signers = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(
            arena,
            accounts[last_nonsigner_index + 1 ..].len,
        );
        for (accounts[last_nonsigner_index + 1 ..]) |signer_idx| {
            try signers.append(try pubkeyToValue(
                arena,
                account_keys.get(@intCast(signer_idx)).?,
            ));
        }
        try info.put(multisig_field_name, try pubkeyToValue(
            arena,
            account_keys.get(@intCast(accounts[last_nonsigner_index])).?,
        ));
        try info.put("signers", .{ .array = signers });
    } else {
        // Single signer case
        try info.put(owner_field_name, try pubkeyToValue(
            arena,
            account_keys.get(@intCast(accounts[last_nonsigner_index])).?,
        ));
    }
}

/// Convert token amount to UI amount format matching Agave's token_amount_to_ui_amount_v3.
fn tokenAmountToUiAmount(arena: Allocator, amount: u64, decimals: u8) !JsonValue {
    var obj = ObjectMap.init(arena);

    const amount_str = try std.fmt.allocPrint(arena, "{d}", .{amount});
    try obj.put("amount", .{ .string = amount_str });
    try obj.put("decimals", .{ .integer = @intCast(decimals) });

    // Calculate UI amount
    if (decimals == 0) {
        const ui_amount_str = try std.fmt.allocPrint(arena, "{d}", .{amount});
        try obj.put("uiAmount", .{ .number_string = try exactFloat(
            arena,
            @floatFromInt(amount),
        ) });
        try obj.put("uiAmountString", .{ .string = ui_amount_str });
    } else {
        const divisor: f64 = std.math.pow(f64, 10.0, @floatFromInt(decimals));
        const ui_amount: f64 = @as(f64, @floatFromInt(amount)) / divisor;
        try obj.put("uiAmount", .{ .number_string = try exactFloat(arena, ui_amount) });
        const ui_amount_str = try sig.runtime.spl_token.realNumberStringTrimmed(
            arena,
            amount,
            decimals,
        );
        try obj.put("uiAmountString", .{ .string = ui_amount_str });
    }

    return .{ .object = obj };
}

/// Format an f64 as a JSON number string matching Rust's serde_json output.
/// Zig's std.json serializes 3.0 as "3e0", but serde serializes it as "3.0".
fn exactFloat(arena: Allocator, value: f64) ![]const u8 {
    var buf: [64]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
    // {d} format omits the decimal point for whole numbers (e.g. "3" instead of "3.0").
    // Append ".0" to match serde's behavior of always including a decimal for floats.
    if (std.mem.indexOf(u8, result, ".") == null) {
        return std.fmt.allocPrint(arena, "{s}.0", .{result});
    }
    return arena.dupe(u8, result);
}

/// Format a UI amount with the specified number of decimal places.
fn formatUiAmount(arena: Allocator, value: f64, decimals: u8) ![]const u8 {
    // Format the float value manually with the right precision
    var buf: [64]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return error.FormatError;

    // Find decimal point
    const dot_idx = std.mem.indexOf(u8, result, ".") orelse {
        // No decimal point, add trailing zeros
        var output = try std.ArrayList(u8).initCapacity(arena, result.len + 1 + decimals);
        try output.appendSlice(arena, result);
        try output.append(arena, '.');
        for (0..decimals) |_| {
            try output.append(arena, '0');
        }
        return try output.toOwnedSlice(arena);
    };

    // Has decimal point - pad or truncate to desired precision
    const after_dot = result.len - dot_idx - 1;
    if (after_dot >= decimals) {
        const slice = result[0 .. dot_idx + 1 + decimals];
        var output = try std.ArrayList(u8).initCapacity(
            arena,
            slice.len,
        );
        // Truncate
        try output.appendSlice(arena, slice);
        return try output.toOwnedSlice(arena);
    } else {
        var output = try std.ArrayList(u8).initCapacity(
            arena,
            result.len + (decimals - after_dot),
        );
        // Pad with zeros
        try output.appendSlice(arena, result);
        for (0..(decimals - after_dot)) |_| {
            try output.append(arena, '0');
        }
        return try output.toOwnedSlice(arena);
    }
}

test "parse_instruction.ParsableProgram.fromID: known programs" {
    try std.testing.expectEqual(
        ParsableProgram.system,
        ParsableProgram.fromID(sig.runtime.program.system.ID).?,
    );
    try std.testing.expectEqual(
        ParsableProgram.vote,
        ParsableProgram.fromID(sig.runtime.program.vote.ID).?,
    );
    try std.testing.expectEqual(
        ParsableProgram.stake,
        ParsableProgram.fromID(sig.runtime.program.stake.ID).?,
    );
    try std.testing.expectEqual(
        ParsableProgram.bpfUpgradeableLoader,
        ParsableProgram.fromID(sig.runtime.program.bpf_loader.v3.ID).?,
    );
    try std.testing.expectEqual(
        ParsableProgram.bpfLoader,
        ParsableProgram.fromID(sig.runtime.program.bpf_loader.v2.ID).?,
    );
    try std.testing.expectEqual(
        ParsableProgram.splToken,
        ParsableProgram.fromID(sig.runtime.ids.TOKEN_PROGRAM_ID).?,
    );
    try std.testing.expectEqual(
        ParsableProgram.splToken,
        ParsableProgram.fromID(sig.runtime.ids.TOKEN_2022_PROGRAM_ID).?,
    );
    try std.testing.expectEqual(
        ParsableProgram.addressLookupTable,
        ParsableProgram.fromID(sig.runtime.program.address_lookup_table.ID).?,
    );
}

test "parse_instruction.ParsableProgram.fromID: unknown program returns null" {
    // Note: Pubkey.ZEROES matches the system program, so use different values
    try std.testing.expectEqual(
        @as(?ParsableProgram, null),
        ParsableProgram.fromID(Pubkey{ .data = [_]u8{0xAB} ** 32 }),
    );
    try std.testing.expectEqual(
        @as(?ParsableProgram, null),
        ParsableProgram.fromID(Pubkey{ .data = [_]u8{0xFF} ** 32 }),
    );
}

test "parse_instruction.ParsableProgram.fromID: spl-memo programs" {
    try std.testing.expectEqual(
        ParsableProgram.splMemo,
        ParsableProgram.fromID(SPL_MEMO_V1_ID).?,
    );
    try std.testing.expectEqual(
        ParsableProgram.splMemo,
        ParsableProgram.fromID(SPL_MEMO_V3_ID).?,
    );
}

test "parse_instruction.ParsableProgram.fromID: spl-associated-token-account" {
    try std.testing.expectEqual(
        ParsableProgram.splAssociatedTokenAccount,
        ParsableProgram.fromID(SPL_ASSOCIATED_TOKEN_ACC_ID).?,
    );
}

test "parse_instruction.parseMemoInstruction: valid UTF-8" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();
    const result = try parseMemoInstruction(allocator, "hello world");
    try std.testing.expectEqualStrings("hello world", result.string);
}

test "parse_instruction.parseMemoInstruction: empty data" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();
    const result = try parseMemoInstruction(allocator, "");
    try std.testing.expectEqualStrings("", result.string);
}

test makeUiPartiallyDecodedInstruction {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();
    const key0 = Pubkey{ .data = [_]u8{1} ** 32 };
    const key1 = Pubkey{ .data = [_]u8{2} ** 32 };
    const key2 = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ key0, key1, key2 };
    const account_keys = AccountKeys.init(&static_keys, null);

    const instruction = sig.ledger.transaction_status.CompiledInstruction{
        .program_id_index = 2,
        .accounts = &.{ 0, 1 },
        .data = &.{ 1, 2, 3 },
    };

    const result = try makeUiPartiallyDecodedInstruction(
        allocator,
        instruction,
        &account_keys,
        3,
    );

    // Verify program ID is base58 of key2
    try std.testing.expectEqualStrings(
        key2.base58String().constSlice(),
        result.programId,
    );
    // Verify accounts are resolved to base58 strings
    try std.testing.expectEqual(@as(usize, 2), result.accounts.len);
    try std.testing.expectEqualStrings(
        key0.base58String().constSlice(),
        result.accounts[0],
    );
    try std.testing.expectEqualStrings(
        key1.base58String().constSlice(),
        result.accounts[1],
    );
    // stackHeight preserved
    try std.testing.expectEqual(@as(?u32, 3), result.stackHeight);
}

test "parse_instruction.parseUiInstruction: unknown program falls back to partially decoded" {
    // Use arena allocator since parse functions allocate many small objects
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    // Use a random pubkey that's not a known program
    const unknown_program = Pubkey{ .data = [_]u8{0xFF} ** 32 };
    const key0 = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{ key0, unknown_program };
    const account_keys = AccountKeys.init(&static_keys, null);

    const instruction = sig.ledger.transaction_status.CompiledInstruction{
        .program_id_index = 1, // unknown_program
        .accounts = &.{0},
        .data = &.{42},
    };

    const result = try parseUiInstruction(
        allocator,
        instruction,
        &account_keys,
        null,
    );

    // Should be a parsed variant (partially decoded)
    switch (result) {
        .parsed => |p| {
            switch (p.*) {
                .partially_decoded => |pd| {
                    try std.testing.expectEqualStrings(
                        unknown_program.base58String().constSlice(),
                        pd.programId,
                    );
                    try std.testing.expectEqual(@as(usize, 1), pd.accounts.len);
                },
                .parsed => return error.UnexpectedResult,
            }
        },
        .compiled => return error.UnexpectedResult,
    }
}

test "parse_instruction.parseInstruction: system transfer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const system_id = sig.runtime.program.system.ID;
    const sender = Pubkey{ .data = [_]u8{1} ** 32 };
    const receiver = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ sender, receiver, system_id };
    const account_keys = AccountKeys.init(&static_keys, null);

    // Build a system transfer instruction (bincode encoded)
    // SystemInstruction::Transfer { lamports: u64 } is tag 2 (u32) + lamports (u64)
    var data: [12]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 2, .little); // transfer variant
    std.mem.writeInt(u64, data[4..12], 1_000_000, .little); // 1M lamports

    const instruction = sig.ledger.transaction_status.CompiledInstruction{
        .program_id_index = 2,
        .accounts = &.{ 0, 1 },
        .data = &data,
    };

    const result = try parseInstruction(
        allocator,
        system_id,
        instruction,
        &account_keys,
        null,
    );

    // Verify it's a parsed instruction
    switch (result) {
        .parsed => |p| {
            switch (p.*) {
                .parsed => |pi| {
                    try std.testing.expectEqualStrings("system", pi.program);
                    // Verify the parsed JSON contains "transfer" type
                    const type_val = pi.parsed.object.get("type").?;
                    try std.testing.expectEqualStrings("transfer", type_val.string);
                    // Verify the info contains lamports
                    const info_val = pi.parsed.object.get("info").?;
                    const lamports = info_val.object.get("lamports").?;
                    try std.testing.expectEqual(@as(i64, 1_000_000), lamports.integer);
                },
                .partially_decoded => return error.UnexpectedResult,
            }
        },
        .compiled => return error.UnexpectedResult,
    }
}

test "parse_instruction.parseInstruction: spl-memo" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const memo_id = SPL_MEMO_V3_ID;
    const signer = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{ signer, memo_id };
    const account_keys = AccountKeys.init(&static_keys, null);

    const memo_text = "Hello, Solana!";
    const instruction = sig.ledger.transaction_status.CompiledInstruction{
        .program_id_index = 1,
        .accounts = &.{0},
        .data = memo_text,
    };

    const result = try parseInstruction(
        allocator,
        memo_id,
        instruction,
        &account_keys,
        null,
    );

    switch (result) {
        .parsed => |p| {
            switch (p.*) {
                .parsed => |pi| {
                    try std.testing.expectEqualStrings("spl-memo", pi.program);
                    // Memo parsed value is a JSON string
                    try std.testing.expectEqualStrings("Hello, Solana!", pi.parsed.string);
                },
                .partially_decoded => return error.UnexpectedResult,
            }
        },
        .compiled => return error.UnexpectedResult,
    }
}

/// Helper to build token extension instruction data:
/// [outer_tag, sub_tag, ...payload]
fn buildExtensionData(comptime outer_tag: u8, sub_tag: u8, payload: []const u8) []const u8 {
    var data: [512]u8 = undefined;
    data[0] = outer_tag;
    data[1] = sub_tag;
    if (payload.len > 0) {
        @memcpy(data[2..][0..payload.len], payload);
    }
    return data[0 .. 2 + payload.len];
}

/// Helper to set up test account keys for extension tests
fn setupExtensionTestKeys(comptime n: usize) struct { keys: [n]Pubkey, account_keys: AccountKeys } {
    var keys: [n]Pubkey = undefined;
    for (0..n) |i| {
        keys[i] = Pubkey{ .data = [_]u8{@intCast(i + 1)} ** 32 };
    }
    return .{ .keys = keys, .account_keys = undefined };
}

test "parseTransferFeeExtension: initializeTransferFeeConfig" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth1 = Pubkey{ .data = [_]u8{2} ** 32 };
    const auth2 = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth1, auth2 };
    const account_keys = AccountKeys.init(&static_keys, null);

    // Build data: sub_tag=0, COption<Pubkey>(1, auth1), COption<Pubkey>(1, auth2), u16 basis_points, u64 max_fee
    var payload: [82]u8 = undefined;
    // COption tag=1 (Some) for auth1
    std.mem.writeInt(u32, payload[0..4], 1, .little);
    @memcpy(payload[4..36], &auth1.data);
    // COption tag=1 (Some) for auth2
    std.mem.writeInt(u32, payload[36..40], 1, .little);
    @memcpy(payload[40..72], &auth2.data);
    // transfer_fee_basis_points=100
    std.mem.writeInt(u16, payload[72..74], 100, .little);
    // maximum_fee=1000000
    std.mem.writeInt(u64, payload[74..82], 1000000, .little);

    const result = try parseTransferFeeExtension(allocator, &([_]u8{0} ++ payload), &.{0}, &account_keys);
    const info = result.object.get("info").?.object;
    try std.testing.expectEqualStrings("initializeTransferFeeConfig", result.object.get("type").?.string);
    try std.testing.expectEqual(@as(i64, 100), info.get("transferFeeBasisPoints").?.integer);
    try std.testing.expectEqual(@as(i64, 1000000), info.get("maximumFee").?.integer);
    try std.testing.expect(info.get("transferFeeConfigAuthority") != null);
    try std.testing.expect(info.get("withdrawWithheldAuthority") != null);
}

test "parseTransferFeeExtension: setTransferFee" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=5, u16 basis_points, u64 max_fee
    var payload: [10]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 50, .little);
    std.mem.writeInt(u64, payload[2..10], 500000, .little);

    const ext_data = [_]u8{5} ++ payload;
    const result = try parseTransferFeeExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    const info = result.object.get("info").?.object;
    try std.testing.expectEqualStrings("setTransferFee", result.object.get("type").?.string);
    try std.testing.expectEqual(@as(i64, 50), info.get("transferFeeBasisPoints").?.integer);
    try std.testing.expectEqual(@as(i64, 500000), info.get("maximumFee").?.integer);
}

test "parseTransferFeeExtension: transferCheckedWithFee" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const source = Pubkey{ .data = [_]u8{1} ** 32 };
    const mint = Pubkey{ .data = [_]u8{2} ** 32 };
    const dest = Pubkey{ .data = [_]u8{3} ** 32 };
    const auth = Pubkey{ .data = [_]u8{4} ** 32 };
    const static_keys = [_]Pubkey{ source, mint, dest, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=1, u64 amount, u8 decimals, u64 fee
    var payload: [17]u8 = undefined;
    std.mem.writeInt(u64, payload[0..8], 1000, .little);
    payload[8] = 6; // decimals
    std.mem.writeInt(u64, payload[9..17], 10, .little);

    const ext_data = [_]u8{1} ++ payload;
    const result = try parseTransferFeeExtension(allocator, &ext_data, &.{ 0, 1, 2, 3 }, &account_keys);
    try std.testing.expectEqualStrings("transferCheckedWithFee", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("source") != null);
    try std.testing.expect(info.get("mint") != null);
    try std.testing.expect(info.get("destination") != null);
    try std.testing.expect(info.get("tokenAmount") != null);
    try std.testing.expect(info.get("feeAmount") != null);
}

test "parseTransferFeeExtension: withdrawWithheldTokensFromMint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const recipient = Pubkey{ .data = [_]u8{2} ** 32 };
    const auth = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ mint, recipient, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{2}; // sub_tag=2, no data
    const result = try parseTransferFeeExtension(allocator, &ext_data, &.{ 0, 1, 2 }, &account_keys);
    try std.testing.expectEqualStrings("withdrawWithheldTokensFromMint", result.object.get("type").?.string);
}

test "parseTransferFeeExtension: harvestWithheldTokensToMint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const source1 = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, source1 };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{4}; // sub_tag=4
    const result = try parseTransferFeeExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("harvestWithheldTokensToMint", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expectEqual(@as(usize, 1), info.get("sourceAccounts").?.array.items.len);
}

test "parseTransferFeeExtension: invalid sub-tag returns error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{99}; // invalid sub_tag
    try std.testing.expectError(error.DeserializationFailed, parseTransferFeeExtension(allocator, &ext_data, &.{0}, &account_keys));
}

test "parseTransferFeeExtension: empty data returns error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    try std.testing.expectError(error.DeserializationFailed, parseTransferFeeExtension(allocator, &.{}, &.{0}, &account_keys));
}

test "parseDefaultAccountStateExtension: initialize" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=0 (Initialize), account_state=2 (Frozen)
    const ext_data = [_]u8{ 0, 2 };
    const result = try parseDefaultAccountStateExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeDefaultAccountState", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expectEqualStrings("frozen", info.get("accountState").?.string);
}

test "parseDefaultAccountStateExtension: update" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const freeze_auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, freeze_auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=1 (Update), account_state=1 (Initialized)
    const ext_data = [_]u8{ 1, 1 };
    const result = try parseDefaultAccountStateExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("updateDefaultAccountState", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expectEqualStrings("initialized", info.get("accountState").?.string);
    // Should have freezeAuthority (single signer)
    try std.testing.expect(info.get("freezeAuthority") != null);
}

test "parseDefaultAccountStateExtension: invalid account state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=0, invalid account_state=5
    const ext_data = [_]u8{ 0, 5 };
    try std.testing.expectError(error.DeserializationFailed, parseDefaultAccountStateExtension(allocator, &ext_data, &.{0}, &account_keys));
}

test "parseDefaultAccountStateExtension: too few accounts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    // update needs 2 accounts
    const ext_data = [_]u8{ 1, 1 };
    try std.testing.expectError(error.NotEnoughSplTokenAccounts, parseDefaultAccountStateExtension(allocator, &ext_data, &.{0}, &account_keys));
}

test "parseMemoTransferExtension: enable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ account, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{0}; // Enable
    const result = try parseMemoTransferExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("enableRequiredMemoTransfers", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("account") != null);
    try std.testing.expect(info.get("owner") != null);
}

test "parseMemoTransferExtension: disable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ account, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{1}; // Disable
    const result = try parseMemoTransferExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("disableRequiredMemoTransfers", result.object.get("type").?.string);
}

test "parseMemoTransferExtension: multisig signers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const multisig = Pubkey{ .data = [_]u8{2} ** 32 };
    const signer1 = Pubkey{ .data = [_]u8{3} ** 32 };
    const signer2 = Pubkey{ .data = [_]u8{4} ** 32 };
    const static_keys = [_]Pubkey{ account, multisig, signer1, signer2 };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{0}; // Enable
    const result = try parseMemoTransferExtension(allocator, &ext_data, &.{ 0, 1, 2, 3 }, &account_keys);
    const info = result.object.get("info").?.object;
    // Multisig case: should have multisigOwner and signers
    try std.testing.expect(info.get("multisigOwner") != null);
    try std.testing.expect(info.get("signers") != null);
    try std.testing.expectEqual(@as(usize, 2), info.get("signers").?.array.items.len);
}

test "parseInterestBearingMintExtension: initialize" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const rate_auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, rate_auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=0, COption<Pubkey>(tag=1, pubkey), i16 rate=500
    var payload: [38]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], 1, .little); // COption tag = Some
    @memcpy(payload[4..36], &rate_auth.data);
    std.mem.writeInt(i16, payload[36..38], 500, .little);
    const ext_data = [_]u8{0} ++ payload;

    const result = try parseInterestBearingMintExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeInterestBearingConfig", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("rateAuthority") != null);
    try std.testing.expectEqual(@as(i64, 500), info.get("rate").?.integer);
}

test "parseInterestBearingMintExtension: updateRate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=1, i16 rate=750
    var payload: [2]u8 = undefined;
    std.mem.writeInt(i16, payload[0..2], 750, .little);
    const ext_data = [_]u8{1} ++ payload;

    const result = try parseInterestBearingMintExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("updateInterestBearingConfigRate", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expectEqual(@as(i64, 750), info.get("newRate").?.integer);
}

test "parseCpiGuardExtension: enable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ account, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{0}; // Enable
    const result = try parseCpiGuardExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("enableCpiGuard", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("account") != null);
    try std.testing.expect(info.get("owner") != null);
}

test "parseCpiGuardExtension: disable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ account, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{1}; // Disable
    const result = try parseCpiGuardExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("disableCpiGuard", result.object.get("type").?.string);
}

test "parseCpiGuardExtension: invalid sub-tag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ account, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{42}; // Invalid
    try std.testing.expectError(error.DeserializationFailed, parseCpiGuardExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys));
}

test "parseTransferHookExtension: initialize" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const program = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth, program };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=0, OptionalNonZeroPubkey authority (32), OptionalNonZeroPubkey program_id (32)
    var payload: [64]u8 = undefined;
    @memcpy(payload[0..32], &auth.data); // authority
    @memcpy(payload[32..64], &program.data); // program_id
    const ext_data = [_]u8{0} ++ payload;

    const result = try parseTransferHookExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeTransferHook", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("authority") != null);
    try std.testing.expect(info.get("programId") != null);
}

test "parseTransferHookExtension: initialize with no authority (zeros)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    // Both authority and program_id are zeros (None)
    const payload: [64]u8 = [_]u8{0} ** 64;
    const ext_data = [_]u8{0} ++ payload;

    const result = try parseTransferHookExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeTransferHook", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    // Zero pubkeys should not appear
    try std.testing.expect(info.get("authority") == null);
    try std.testing.expect(info.get("programId") == null);
}

test "parseTransferHookExtension: update" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const new_program = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth, new_program };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=1, OptionalNonZeroPubkey program_id (32)
    var payload: [32]u8 = undefined;
    @memcpy(payload[0..32], &new_program.data);
    const ext_data = [_]u8{1} ++ payload;

    const result = try parseTransferHookExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("updateTransferHook", result.object.get("type").?.string);
}

test "parseMetadataPointerExtension: initialize" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const metadata = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth, metadata };
    const account_keys = AccountKeys.init(&static_keys, null);

    var payload: [64]u8 = undefined;
    @memcpy(payload[0..32], &auth.data);
    @memcpy(payload[32..64], &metadata.data);
    const ext_data = [_]u8{0} ++ payload;

    const result = try parseMetadataPointerExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeMetadataPointer", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("authority") != null);
    try std.testing.expect(info.get("metadataAddress") != null);
}

test "parseMetadataPointerExtension: update" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const new_metadata = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth, new_metadata };
    const account_keys = AccountKeys.init(&static_keys, null);

    var payload: [32]u8 = undefined;
    @memcpy(payload[0..32], &new_metadata.data);
    const ext_data = [_]u8{1} ++ payload;

    const result = try parseMetadataPointerExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("updateMetadataPointer", result.object.get("type").?.string);
}

test "parseGroupPointerExtension: initialize" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const group = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth, group };
    const account_keys = AccountKeys.init(&static_keys, null);

    var payload: [64]u8 = undefined;
    @memcpy(payload[0..32], &auth.data);
    @memcpy(payload[32..64], &group.data);
    const ext_data = [_]u8{0} ++ payload;

    const result = try parseGroupPointerExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeGroupPointer", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("authority") != null);
    try std.testing.expect(info.get("groupAddress") != null);
}

test "parseGroupPointerExtension: update" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    const payload: [32]u8 = [_]u8{0} ** 32; // zeros = no group address
    const ext_data = [_]u8{1} ++ payload;

    const result = try parseGroupPointerExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("updateGroupPointer", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    // Zero pubkey is None, should not be in output
    try std.testing.expect(info.get("groupAddress") == null);
}

test "parseGroupMemberPointerExtension: initialize and update" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const member = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth, member };
    const account_keys = AccountKeys.init(&static_keys, null);

    // Initialize
    var payload_init: [64]u8 = undefined;
    @memcpy(payload_init[0..32], &auth.data);
    @memcpy(payload_init[32..64], &member.data);
    const ext_data_init = [_]u8{0} ++ payload_init;
    const result_init = try parseGroupMemberPointerExtension(allocator, &ext_data_init, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeGroupMemberPointer", result_init.object.get("type").?.string);
    const info_init = result_init.object.get("info").?.object;
    try std.testing.expect(info_init.get("memberAddress") != null);

    // Update
    var payload_update: [32]u8 = undefined;
    @memcpy(payload_update[0..32], &member.data);
    const ext_data_update = [_]u8{1} ++ payload_update;
    const result_update = try parseGroupMemberPointerExtension(allocator, &ext_data_update, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("updateGroupMemberPointer", result_update.object.get("type").?.string);
}

test "parsePausableExtension: initialize" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=0, OptionalNonZeroPubkey authority
    var payload: [32]u8 = undefined;
    @memcpy(payload[0..32], &auth.data);
    const ext_data = [_]u8{0} ++ payload;

    const result = try parsePausableExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializePausableConfig", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("authority") != null);
}

test "parsePausableExtension: initialize with no authority" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    // All zeros = None authority
    const payload = [_]u8{0} ** 32;
    const ext_data = [_]u8{0} ++ payload;

    const result = try parsePausableExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializePausableConfig", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    // Null authority
    try std.testing.expect(info.get("authority").?.null == {});
}

test "parsePausableExtension: pause" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{1}; // Pause
    const result = try parsePausableExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("pause", result.object.get("type").?.string);
}

test "parsePausableExtension: resume" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{2}; // Resume
    const result = try parsePausableExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("resume", result.object.get("type").?.string);
}

test "parsePausableExtension: invalid sub-tag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{3}; // Invalid
    try std.testing.expectError(error.DeserializationFailed, parsePausableExtension(allocator, &ext_data, &.{0}, &account_keys));
}

test "parseScaledUiAmountExtension: initialize" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=0, OptionalNonZeroPubkey authority (32 bytes), f64 multiplier (8 bytes)
    var payload: [40]u8 = undefined;
    @memcpy(payload[0..32], &auth.data); // authority
    const multiplier: f64 = 1.5;
    std.mem.writeInt(u64, payload[32..40], @bitCast(multiplier), .little);
    const ext_data = [_]u8{0} ++ payload;

    const result = try parseScaledUiAmountExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeScaledUiAmountConfig", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("authority") != null);
    try std.testing.expect(info.get("multiplier") != null);
}

test "parseScaledUiAmountExtension: updateMultiplier" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=1, f64 multiplier (8 bytes), i64 timestamp (8 bytes)
    var payload: [16]u8 = undefined;
    const multiplier: f64 = 2.0;
    std.mem.writeInt(u64, payload[0..8], @bitCast(multiplier), .little);
    std.mem.writeInt(i64, payload[8..16], 1700000000, .little);
    const ext_data = [_]u8{1} ++ payload;

    const result = try parseScaledUiAmountExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("updateMultiplier", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("newMultiplier") != null);
    try std.testing.expectEqual(@as(i64, 1700000000), info.get("newMultiplierTimestamp").?.integer);
}

test "parseConfidentialTransferExtension: approveAccount" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const mint = Pubkey{ .data = [_]u8{2} ** 32 };
    const authority = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ account, mint, authority };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{3}; // ApproveAccount
    const result = try parseConfidentialTransferExtension(allocator, &ext_data, &.{ 0, 1, 2 }, &account_keys);
    try std.testing.expectEqualStrings("approveConfidentialTransferAccount", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("account") != null);
    try std.testing.expect(info.get("mint") != null);
    try std.testing.expect(info.get("confidentialTransferAuditorAuthority") != null);
}

test "parseConfidentialTransferExtension: configureAccountWithRegistry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const mint = Pubkey{ .data = [_]u8{2} ** 32 };
    const registry = Pubkey{ .data = [_]u8{3} ** 32 };
    const static_keys = [_]Pubkey{ account, mint, registry };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{14}; // ConfigureAccountWithRegistry
    const result = try parseConfidentialTransferExtension(allocator, &ext_data, &.{ 0, 1, 2 }, &account_keys);
    try std.testing.expectEqualStrings("configureConfidentialAccountWithRegistry", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("registry") != null);
}

test "parseConfidentialTransferExtension: enableDisableCredits" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ account, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    // Enable confidential credits (tag=9)
    const ext_data_enable = [_]u8{9};
    const result_enable = try parseConfidentialTransferExtension(allocator, &ext_data_enable, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("enableConfidentialTransferConfidentialCredits", result_enable.object.get("type").?.string);

    // Disable confidential credits (tag=10)
    const ext_data_disable = [_]u8{10};
    const result_disable = try parseConfidentialTransferExtension(allocator, &ext_data_disable, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("disableConfidentialTransferConfidentialCredits", result_disable.object.get("type").?.string);

    // Enable non-confidential credits (tag=11)
    const ext_data_enable_nc = [_]u8{11};
    const result_enable_nc = try parseConfidentialTransferExtension(allocator, &ext_data_enable_nc, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("enableConfidentialTransferNonConfidentialCredits", result_enable_nc.object.get("type").?.string);

    // Disable non-confidential credits (tag=12)
    const ext_data_disable_nc = [_]u8{12};
    const result_disable_nc = try parseConfidentialTransferExtension(allocator, &ext_data_disable_nc, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("disableConfidentialTransferNonConfidentialCredits", result_disable_nc.object.get("type").?.string);
}

test "parseConfidentialTransferExtension: invalid sub-tag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{99};
    try std.testing.expectError(error.DeserializationFailed, parseConfidentialTransferExtension(allocator, &ext_data, &.{0}, &account_keys));
}

test "parseConfidentialTransferFeeExtension: initializeConfig" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // sub_tag=0, OptionalNonZeroPubkey authority (32 bytes)
    var payload: [32]u8 = undefined;
    @memcpy(payload[0..32], &auth.data);
    const ext_data = [_]u8{0} ++ payload;

    const result = try parseConfidentialTransferFeeExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeConfidentialTransferFeeConfig", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expect(info.get("authority") != null);
}

test "parseConfidentialTransferFeeExtension: harvestWithheldTokensToMint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const source = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, source };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{3}; // HarvestWithheldTokensToMint
    const result = try parseConfidentialTransferFeeExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("harvestWithheldConfidentialTransferTokensToMint", result.object.get("type").?.string);
    const info = result.object.get("info").?.object;
    try std.testing.expectEqual(@as(usize, 1), info.get("sourceAccounts").?.array.items.len);
}

test "parseConfidentialTransferFeeExtension: enableDisableHarvestToMint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ account, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    // Enable (tag=4)
    const ext_enable = [_]u8{4};
    const result_enable = try parseConfidentialTransferFeeExtension(allocator, &ext_enable, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("enableConfidentialTransferFeeHarvestToMint", result_enable.object.get("type").?.string);

    // Disable (tag=5)
    const ext_disable = [_]u8{5};
    const result_disable = try parseConfidentialTransferFeeExtension(allocator, &ext_disable, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("disableConfidentialTransferFeeHarvestToMint", result_disable.object.get("type").?.string);
}

test "parseConfidentialMintBurnExtension: initializeMint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{0};
    const result = try parseConfidentialMintBurnExtension(allocator, &ext_data, &.{0}, &account_keys);
    try std.testing.expectEqualStrings("initializeConfidentialMintBurnMint", result.object.get("type").?.string);
}

test "parseConfidentialMintBurnExtension: applyPendingBurn" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    const ext_data = [_]u8{5}; // ApplyPendingBurn
    const result = try parseConfidentialMintBurnExtension(allocator, &ext_data, &.{ 0, 1 }, &account_keys);
    try std.testing.expectEqualStrings("applyPendingBurn", result.object.get("type").?.string);
}

test "parseTokenInstruction: defaultAccountState extension via outer dispatch" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    // outer tag=28 (defaultAccountStateExtension), sub_tag=0 (Initialize), account_state=2 (Frozen)
    const data = [_]u8{ 28, 0, 2 };
    const instruction = sig.ledger.transaction_status.CompiledInstruction{
        .program_id_index = 0,
        .accounts = &.{0},
        .data = &data,
    };

    const result = try parseTokenInstruction(allocator, instruction, &account_keys);
    try std.testing.expectEqualStrings("initializeDefaultAccountState", result.object.get("type").?.string);
}

test "parseTokenInstruction: memoTransfer extension via outer dispatch" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ account, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    // outer tag=30 (memoTransferExtension), sub_tag=0 (Enable)
    const data = [_]u8{ 30, 0 };
    const instruction = sig.ledger.transaction_status.CompiledInstruction{
        .program_id_index = 0,
        .accounts = &.{ 0, 1 },
        .data = &data,
    };

    const result = try parseTokenInstruction(allocator, instruction, &account_keys);
    try std.testing.expectEqualStrings("enableRequiredMemoTransfers", result.object.get("type").?.string);
}

test "parseTokenInstruction: cpiGuard extension via outer dispatch" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const account = Pubkey{ .data = [_]u8{1} ** 32 };
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ account, owner };
    const account_keys = AccountKeys.init(&static_keys, null);

    // outer tag=34 (cpiGuardExtension), sub_tag=1 (Disable)
    const data = [_]u8{ 34, 1 };
    const instruction = sig.ledger.transaction_status.CompiledInstruction{
        .program_id_index = 0,
        .accounts = &.{ 0, 1 },
        .data = &data,
    };

    const result = try parseTokenInstruction(allocator, instruction, &account_keys);
    try std.testing.expectEqualStrings("disableCpiGuard", result.object.get("type").?.string);
}

test "parseTokenInstruction: pausable extension via outer dispatch" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const auth = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ mint, auth };
    const account_keys = AccountKeys.init(&static_keys, null);

    // outer tag=44 (pausableExtension), sub_tag=1 (Pause)
    const data = [_]u8{ 44, 1 };
    const instruction = sig.ledger.transaction_status.CompiledInstruction{
        .program_id_index = 0,
        .accounts = &.{ 0, 1 },
        .data = &data,
    };

    const result = try parseTokenInstruction(allocator, instruction, &account_keys);
    try std.testing.expectEqualStrings("pause", result.object.get("type").?.string);
}

test "parseTokenInstruction: extension with insufficient data returns error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{mint};
    const account_keys = AccountKeys.init(&static_keys, null);

    // outer tag=28 (defaultAccountStateExtension) with no sub-data
    const data = [_]u8{28};
    const instruction = sig.ledger.transaction_status.CompiledInstruction{
        .program_id_index = 0,
        .accounts = &.{0},
        .data = &data,
    };

    try std.testing.expectError(error.DeserializationFailed, parseTokenInstruction(allocator, instruction, &account_keys));
}

test "readOptionalNonZeroPubkey: non-zero returns pubkey" {
    const data = [_]u8{0xAA} ** 64;
    const result = readOptionalNonZeroPubkey(&data, 0);
    try std.testing.expect(result != null);
    try std.testing.expectEqual([_]u8{0xAA} ** 32, result.?.data);
}

test "readOptionalNonZeroPubkey: zeros returns null" {
    const data = [_]u8{0} ** 64;
    const result = readOptionalNonZeroPubkey(&data, 0);
    try std.testing.expect(result == null);
}

test "readOptionalNonZeroPubkey: offset" {
    var data: [48]u8 = undefined;
    @memset(data[0..16], 0);
    @memset(data[16..48], 0xBB);
    const result = readOptionalNonZeroPubkey(&data, 16);
    try std.testing.expect(result != null);
    try std.testing.expectEqual([_]u8{0xBB} ** 32, result.?.data);
}

test "readOptionalNonZeroPubkey: insufficient data returns null" {
    const data = [_]u8{0xAA} ** 16; // Only 16 bytes, need 32
    const result = readOptionalNonZeroPubkey(&data, 0);
    try std.testing.expect(result == null);
}

test "readCOptionPubkey: Some variant" {
    var data: [36]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 1, .little); // tag = Some
    @memset(data[4..36], 0xCC);
    const result = try readCOptionPubkey(&data, 0);
    try std.testing.expect(result.pubkey != null);
    try std.testing.expectEqual(@as(usize, 36), result.len);
    try std.testing.expectEqual([_]u8{0xCC} ** 32, result.pubkey.?.data);
}

test "readCOptionPubkey: None variant" {
    var data: [4]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 0, .little); // tag = None
    const result = try readCOptionPubkey(&data, 0);
    try std.testing.expect(result.pubkey == null);
    try std.testing.expectEqual(@as(usize, 4), result.len);
}

test "readCOptionPubkey: invalid tag" {
    var data: [36]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 2, .little); // Invalid tag
    try std.testing.expectError(error.DeserializationFailed, readCOptionPubkey(&data, 0));
}

test "readCOptionPubkey: insufficient data for tag" {
    const data = [_]u8{ 0, 0 }; // Only 2 bytes, need 4 for tag
    try std.testing.expectError(error.DeserializationFailed, readCOptionPubkey(&data, 0));
}

test "readCOptionPubkey: Some but insufficient data for pubkey" {
    var data: [8]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 1, .little); // tag = Some
    // Only 4 more bytes, need 32
    try std.testing.expectError(error.DeserializationFailed, readCOptionPubkey(&data, 0));
}
