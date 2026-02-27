//! Instruction parsers for jsonParsed encoding mode.
//!
//! Parses compiled instructions from known programs (vote, system, spl-memo)
//! into structured JSON representations matching Agave's output format.
//! Unknown programs fall back to partially decoded representation.

const std = @import("std");
const sig = @import("../../sig.zig");
const base58 = @import("base58");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const JsonValue = std.json.Value;
const ObjectMap = std.json.ObjectMap;

pub const AccountKeys = @import("AccountKeys.zig");
pub const ReservedAccountKeys = @import("ReservedAccountKeys.zig");
pub const LoadedMessage = @import("LoadedMessage.zig");

const vote_program = sig.runtime.program.vote;
const system_program = sig.runtime.program.system;
const address_lookup_table_program = sig.runtime.program.address_lookup_table;
const stake_program = sig.runtime.program.stake;
const bpf_loader = sig.runtime.program.bpf_loader;
const VoteInstruction = vote_program.Instruction;
const SystemInstruction = system_program.Instruction;
const AddressLookupTableInstruction = address_lookup_table_program.Instruction;
const StakeInstruction = stake_program.Instruction;
const StakeLockupArgs = stake_program.LockupArgs;
const BpfUpgradeableLoaderInstruction = bpf_loader.v3.Instruction;

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

    pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

    pub fn jsonStringify(self: @This(), jw: anytype) !void {
        switch (self) {
            .compiled => |c| try c.jsonStringify(jw),
            .parsed => |p| try p.jsonStringify(jw),
        }
    }
};

pub const UiParsedInstruction = union(enum) {
    parsed: ParsedInstruction,
    partially_decoded: UiPartiallyDecodedInstruction,

    pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

    pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

    pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

    pub fn jsonStringify(self: @This(), jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("parsed");
        // // Write pre-serialized JSON raw
        // try jw.beginWriteRaw();
        try jw.write(self.parsed);
        // jw.endWriteRaw();
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
    allocator: Allocator,
    value: UiParsedInstruction,
) !UiInstruction {
    const ptr = try allocator.create(UiParsedInstruction);
    ptr.* = value;
    return .{ .parsed = ptr };
}

pub fn parseUiInstruction(
    allocator: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
    stack_height: ?u32,
) !UiInstruction {
    const ixn_idx: usize = @intCast(instruction.program_id_index);
    const program_id = account_keys.get(ixn_idx).?;
    return parseInstruction(
        allocator,
        program_id,
        instruction,
        account_keys,
        stack_height,
    ) catch {
        return allocParsed(allocator, .{ .partially_decoded = try makeUiPartiallyDecodedInstruction(
            allocator,
            instruction,
            account_keys,
            stack_height,
        ) });
    };
}

pub fn parseUiInnerInstructions(
    allocator: Allocator,
    inner_instructions: sig.ledger.transaction_status.InnerInstructions,
    account_keys: *const AccountKeys,
) !UiInnerInstructions {
    var instructions = try allocator.alloc(UiInstruction, inner_instructions.instructions.len);
    for (inner_instructions.instructions, 0..) |ixn, i| {
        instructions[i] = try parseUiInstruction(
            allocator,
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
pub fn parseInstruction(
    allocator: Allocator,
    program_id: Pubkey,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
    stack_height: ?u32,
) !UiInstruction {
    const program_name = ParsableProgram.fromID(program_id) orelse return error.ProgramNotParsable;

    switch (program_name) {
        .addressLookupTable => {
            return allocParsed(allocator, .{ .parsed = .{
                .program = "address-lookup-table",
                .program_id = try allocator.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseAddressLookupTableInstruction(
                    allocator,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .splAssociatedTokenAccount => {
            return allocParsed(allocator, .{ .parsed = .{
                .program = "spl-associated-token-account",
                .program_id = try allocator.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseAssociatedTokenInstruction(
                    allocator,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .splMemo => {
            return allocParsed(allocator, .{ .parsed = .{
                .program = "spl-memo",
                .program_id = try allocator.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseMemoInstruction(allocator, instruction.data),
                .stack_height = stack_height,
            } });
        },
        .splToken => {
            return allocParsed(allocator, .{ .parsed = .{
                .program = "spl-token",
                .program_id = try allocator.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseTokenInstruction(
                    allocator,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .bpfLoader => {
            return allocParsed(allocator, .{ .parsed = .{
                .program = "bpf-loader",
                .program_id = try allocator.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseBpfLoaderInstruction(
                    allocator,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .bpfUpgradeableLoader => {
            return allocParsed(allocator, .{ .parsed = .{
                .program = "bpf-upgradeable-loader",
                .program_id = try allocator.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseBpfUpgradeableLoaderInstruction(
                    allocator,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .stake => {
            return allocParsed(allocator, .{ .parsed = .{
                .program = @tagName(program_name),
                .program_id = try allocator.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseStakeInstruction(
                    allocator,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .system => {
            return allocParsed(allocator, .{ .parsed = .{
                .program = @tagName(program_name),
                .program_id = try allocator.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseSystemInstruction(
                    allocator,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
        .vote => {
            return allocParsed(allocator, .{ .parsed = .{
                .program = @tagName(program_name),
                .program_id = try allocator.dupe(u8, program_id.base58String().constSlice()),
                .parsed = try parseVoteInstruction(
                    allocator,
                    instruction,
                    account_keys,
                ),
                .stack_height = stack_height,
            } });
        },
    }
}

pub fn makeUiPartiallyDecodedInstruction(
    allocator: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
    stack_height: ?u32,
) !UiPartiallyDecodedInstruction {
    const program_id_index: usize = @intCast(instruction.program_id_index);
    const program_id_str = if (account_keys.get(program_id_index)) |pk|
        try allocator.dupe(u8, pk.base58String().constSlice())
    else
        try allocator.dupe(u8, "unknown");

    var accounts = try allocator.alloc([]const u8, instruction.accounts.len);
    for (instruction.accounts, 0..) |acct_idx, i| {
        accounts[i] = if (account_keys.get(@intCast(acct_idx))) |pk|
            try allocator.dupe(u8, pk.base58String().constSlice())
        else
            try allocator.dupe(u8, "unknown");
    }

    return .{
        .programId = program_id_str,
        .accounts = accounts,
        .data = blk: {
            const buf = try allocator.alloc(u8, base58.encodedMaxSize(instruction.data.len));
            defer allocator.free(buf);
            const len = base58.Table.BITCOIN.encode(buf, instruction.data);
            break :blk try allocator.dupe(u8, buf[0..len]);
        },
        .stackHeight = stack_height,
    };
}

/// Build a partially decoded instruction (fallback for unknown programs or parse failures).
fn buildPartiallyDecoded(
    allocator: Allocator,
    program_id: []const u8,
    data: []const u8,
    account_indices: []const u8,
    all_keys: []const []const u8,
    stack_height: ?u32,
) !ParsedInstruction {
    const resolved_accounts = try allocator.alloc([]const u8, account_indices.len);
    for (account_indices, 0..) |acct_idx, j| {
        resolved_accounts[j] = if (acct_idx < all_keys.len)
            try allocator.dupe(u8[acct_idx])
        else
            try allocator.dupe(u8, "unknown");
    }

    const base58_encoder = base58.Table.BITCOIN;
    const data_str = base58_encoder.encodeAlloc(allocator, data) catch {
        return error.EncodingError;
    };

    return .{ .partially_decoded = .{
        .programId = try allocator.dupe(u8, program_id),
        .accounts = resolved_accounts,
        .data = data_str,
        .stackHeight = stack_height,
    } };
}

// ============================================================================
// SPL Memo Parser
// ============================================================================

/// Parse an SPL Memo instruction. The data is simply UTF-8 text.
/// Returns a JSON string value.
fn parseMemoInstruction(allocator: Allocator, data: []const u8) !JsonValue {
    // Validate UTF-8
    if (!std.unicode.utf8ValidateSlice(data)) return error.InvalidUtf8;

    // Return as a JSON string value
    return .{ .string = try allocator.dupe(u8, data) };
}

// ============================================================================
// Vote Instruction Parser
// ============================================================================

/// Parse a vote instruction into a JSON Value.
fn parseVoteInstruction(
    allocator: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(allocator, VoteInstruction, instruction.data, .{}) catch {
        return error.DeserializationFailed;
    };
    defer ix.deinit(allocator);
    for (instruction.accounts) |acc_idx| {
        // Runtime should prevent this from ever happening
        if (acc_idx >= account_keys.len()) return error.InstructionKeyMismatch;
    }

    var result = ObjectMap.init(allocator);
    errdefer result.deinit();

    switch (ix) {
        .initialize_account => |init_acct| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("node", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("authorizedVoter", try pubkeyToValue(
                allocator,
                init_acct.authorized_voter,
            ));
            try info.put("authorizedWithdrawer", try pubkeyToValue(
                allocator,
                init_acct.authorized_withdrawer,
            ));
            try info.put("commission", .{ .integer = @intCast(init_acct.commission) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initialize" });
        },
        .authorize => |auth| {
            try checkNumVoteAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(allocator, auth.new_authority));
            try info.put("authorityType", voteAuthorizeToValue(auth.vote_authorize));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorize" });
        },
        .authorize_with_seed => |aws| {
            try checkNumVoteAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("authorityBaseKey", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityOwner", try pubkeyToValue(
                allocator,
                aws.current_authority_derived_key_owner,
            ));
            try info.put("authoritySeed", .{ .string = aws.current_authority_derived_key_seed });
            try info.put("authorityType", voteAuthorizeToValue(aws.authorization_type));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(allocator, aws.new_authority));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeWithSeed" });
        },
        .authorize_checked_with_seed => |acws| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("authorityBaseKey", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityOwner", try pubkeyToValue(
                allocator,
                acws.current_authority_derived_key_owner,
            ));
            try info.put("authoritySeed", .{ .string = acws.current_authority_derived_key_seed });
            try info.put("authorityType", voteAuthorizeToValue(acws.authorization_type));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeCheckedWithSeed" });
        },
        .vote => |v| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("slotHashesSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("vote", try voteToValue(allocator, v.vote));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "vote" });
        },
        .update_vote_state => |vsu| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteStateUpdate", try voteStateUpdateToValue(
                allocator,
                vsu.vote_state_update,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updatevotestate" });
        },
        .update_vote_state_switch => |vsus| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("hash", try hashToValue(allocator, vsus.hash));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteStateUpdate", try voteStateUpdateToValue(
                allocator,
                vsus.vote_state_update,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updatevotestateswitch" });
        },
        .compact_update_vote_state => |cvsu| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteStateUpdate", try voteStateUpdateToValue(
                allocator,
                cvsu.vote_state_update,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "compactupdatevotestate" });
        },
        .compact_update_vote_state_switch => |cvsus| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("hash", try hashToValue(allocator, cvsus.hash));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteStateUpdate", try voteStateUpdateToValue(
                allocator,
                cvsus.vote_state_update,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "compactupdatevotestateswitch" });
        },
        .tower_sync => |ts| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("towerSync", try towerSyncToValue(allocator, ts.tower_sync));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "towersync" });
        },
        .tower_sync_switch => |tss| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("hash", try hashToValue(allocator, tss.hash));
            try info.put("towerSync", try towerSyncToValue(allocator, tss.tower_sync));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "towersyncswitch" });
        },
        .withdraw => |lamports| {
            try checkNumVoteAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("withdrawAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdraw" });
        },
        .update_validator_identity => {
            try checkNumVoteAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("newValidatorIdentity", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("withdrawAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateValidatorIdentity" });
        },
        .update_commission => |commission| {
            try checkNumVoteAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("commission", .{ .integer = @intCast(commission) });
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("withdrawAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "updateCommission" });
        },
        .vote_switch => |vs| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("hash", try hashToValue(allocator, vs.hash));
            try info.put("slotHashesSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("vote", try voteToValue(allocator, vs.vote));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "voteSwitch" });
        },
        .authorize_checked => |auth_type| {
            try checkNumVoteAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityType", voteAuthorizeToValue(auth_type));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
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
fn pubkeyToValue(allocator: std.mem.Allocator, pubkey: Pubkey) !JsonValue {
    return .{ .string = try allocator.dupe(u8, pubkey.base58String().constSlice()) };
}

/// Convert a Hash to a JSON string value
fn hashToValue(allocator: std.mem.Allocator, hash: Hash) !JsonValue {
    return .{ .string = try allocator.dupe(u8, hash.base58String().constSlice()) };
}

/// Convert VoteAuthorize to a JSON string value
fn voteAuthorizeToValue(auth: vote_program.vote_instruction.VoteAuthorize) JsonValue {
    return .{ .string = switch (auth) {
        .voter => "Voter",
        .withdrawer => "Withdrawer",
    } };
}

/// Convert a Vote to a JSON Value object
fn voteToValue(allocator: Allocator, vote: vote_program.state.Vote) !JsonValue {
    var obj = ObjectMap.init(allocator);
    errdefer obj.deinit();

    try obj.put("hash", try hashToValue(allocator, vote.hash));

    var slots_array = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(
        allocator,
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
fn voteStateUpdateToValue(allocator: Allocator, vsu: vote_program.state.VoteStateUpdate) !JsonValue {
    var obj = ObjectMap.init(allocator);
    errdefer obj.deinit();

    try obj.put("hash", try hashToValue(allocator, vsu.hash));
    try obj.put("lockouts", try lockoutsToValue(allocator, vsu.lockouts.items));
    try obj.put("root", if (vsu.root) |root| .{ .integer = @intCast(root) } else .null);
    try obj.put("timestamp", if (vsu.timestamp) |ts| .{ .integer = ts } else .null);

    return .{ .object = obj };
}

/// Convert a TowerSync to a JSON Value object
fn towerSyncToValue(allocator: Allocator, ts: vote_program.state.TowerSync) !JsonValue {
    var obj = ObjectMap.init(allocator);
    errdefer obj.deinit();

    try obj.put("blockId", try hashToValue(allocator, ts.block_id));
    try obj.put("hash", try hashToValue(allocator, ts.hash));
    try obj.put("lockouts", try lockoutsToValue(allocator, ts.lockouts.items));
    try obj.put("root", if (ts.root) |root| .{ .integer = @intCast(root) } else .null);
    try obj.put("timestamp", if (ts.timestamp) |timestamp| .{ .integer = timestamp } else .null);

    return .{ .object = obj };
}

/// Convert an array of Lockouts to a JSON array value
fn lockoutsToValue(allocator: Allocator, lockouts: []const vote_program.state.Lockout) !JsonValue {
    var arr = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(
        allocator,
        lockouts.len,
    );
    errdefer arr.deinit();

    for (lockouts) |lockout| {
        var lockout_obj = ObjectMap.init(allocator);
        try lockout_obj.put(
            "confirmation_count",
            .{ .integer = @intCast(lockout.confirmation_count) },
        );
        try lockout_obj.put("slot", .{ .integer = @intCast(lockout.slot) });
        try arr.append(.{ .object = lockout_obj });
    }

    return .{ .array = arr };
}

// ============================================================================
// System Instruction Parser
// ============================================================================

/// Parse a system instruction into a JSON Value.
fn parseSystemInstruction(
    allocator: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(
        allocator,
        SystemInstruction,
        instruction.data,
        .{},
    ) catch {
        return error.DeserializationFailed;
    };
    defer ix.deinit(allocator);
    for (instruction.accounts) |acc_idx| {
        // Runtime should prevent this from ever happening
        if (acc_idx >= account_keys.len()) return error.InstructionKeyMismatch;
    }

    var result = ObjectMap.init(allocator);
    errdefer result.deinit();

    switch (ix) {
        .create_account => |ca| {
            try checkNumSystemAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("lamports", .{ .integer = @intCast(ca.lamports) });
            try info.put("newAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(allocator, ca.owner));
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("space", .{ .integer = @intCast(ca.space) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createAccount" });
        },
        .assign => |a| {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("owner", try pubkeyToValue(allocator, a.owner));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "assign" });
        },
        .transfer => |t| {
            try checkNumSystemAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(t.lamports) });
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "transfer" });
        },
        .create_account_with_seed => |cas| {
            try checkNumSystemAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("base", try pubkeyToValue(allocator, cas.base));
            try info.put("lamports", .{ .integer = @intCast(cas.lamports) });
            try info.put("newAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(allocator, cas.owner));
            try info.put("seed", .{ .string = cas.seed });
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("space", .{ .integer = @intCast(cas.space) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createAccountWithSeed" });
        },
        .advance_nonce_account => {
            try checkNumSystemAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("nonceAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nonceAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("recentBlockhashesSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "advanceNonce" });
        },
        .withdraw_nonce_account => |lamports| {
            try checkNumSystemAccounts(instruction.accounts, 5);
            var info = ObjectMap.init(allocator);
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("nonceAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nonceAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("recentBlockhashesSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdrawFromNonce" });
        },
        .initialize_nonce_account => |authority| {
            try checkNumSystemAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("nonceAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nonceAuthority", try pubkeyToValue(allocator, authority));
            try info.put("recentBlockhashesSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeNonce" });
        },
        .authorize_nonce_account => |new_authority| {
            try checkNumSystemAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("newAuthorized", try pubkeyToValue(allocator, new_authority));
            try info.put("nonceAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nonceAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeNonce" });
        },
        .allocate => |a| {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("space", .{ .integer = @intCast(a.space) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "allocate" });
        },
        .allocate_with_seed => |aws| {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("base", try pubkeyToValue(allocator, aws.base));
            try info.put("owner", try pubkeyToValue(allocator, aws.owner));
            try info.put("seed", .{ .string = aws.seed });
            try info.put("space", .{ .integer = @intCast(aws.space) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "allocateWithSeed" });
        },
        .assign_with_seed => |aws| {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("base", try pubkeyToValue(allocator, aws.base));
            try info.put("owner", try pubkeyToValue(allocator, aws.owner));
            try info.put("seed", .{ .string = aws.seed });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "assignWithSeed" });
        },
        .transfer_with_seed => |tws| {
            try checkNumSystemAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(tws.lamports) });
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("sourceBase", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("sourceOwner", try pubkeyToValue(allocator, tws.from_owner));
            try info.put("sourceSeed", .{ .string = tws.from_seed });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "transferWithSeed" });
        },
        .upgrade_nonce_account => {
            try checkNumSystemAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("nonceAccount", try pubkeyToValue(
                allocator,
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

// ============================================================================
// Address Lookup Table Instruction Parser
// ============================================================================

/// Parse an address lookup table instruction into a JSON Value.
fn parseAddressLookupTableInstruction(
    allocator: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(
        allocator,
        AddressLookupTableInstruction,
        instruction.data,
        .{},
    ) catch {
        return error.DeserializationFailed;
    };
    defer {
        switch (ix) {
            .ExtendLookupTable => |ext| allocator.free(ext.new_addresses),
            else => {},
        }
    }

    for (instruction.accounts) |acc_idx| {
        // Runtime should prevent this from ever happening
        if (acc_idx >= account_keys.len()) return error.InstructionKeyMismatch;
    }

    var result = ObjectMap.init(allocator);
    errdefer result.deinit();

    switch (ix) {
        .CreateLookupTable => |create| {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("bumpSeed", .{ .integer = @intCast(create.bump_seed) });
            try info.put("lookupTableAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("payerAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("recentSlot", .{ .integer = @intCast(create.recent_slot) });
            try info.put("systemProgram", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createLookupTable" });
        },
        .FreezeLookupTable => {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("lookupTableAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "freezeLookupTable" });
        },
        .ExtendLookupTable => |extend| {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("lookupTableAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Build newAddresses array
            var new_addresses_array = try std.array_list.AlignedManaged(
                JsonValue,
                null,
            ).initCapacity(
                allocator,
                extend.new_addresses.len,
            );
            for (extend.new_addresses) |addr| {
                try new_addresses_array.append(try pubkeyToValue(allocator, addr));
            }
            try info.put("newAddresses", .{ .array = new_addresses_array });
            // Optional payer and system program (only if >= 4 accounts)
            if (instruction.accounts.len >= 4) {
                try info.put("payerAccount", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[2])).?,
                ));
                try info.put("systemProgram", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[3])).?,
                ));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "extendLookupTable" });
        },
        .DeactivateLookupTable => {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("lookupTableAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "deactivateLookupTable" });
        },
        .CloseLookupTable => {
            try checkNumAddressLookupTableAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("lookupTableAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("lookupTableAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("recipient", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "closeLookupTable" });
        },
    }

    return .{ .object = result };
}

// ============================================================================
// Stake Instruction Parser
// ============================================================================

/// Parse a stake instruction into a JSON Value.
fn parseStakeInstruction(
    allocator: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(allocator, StakeInstruction, instruction.data, .{}) catch {
        return error.DeserializationFailed;
    };
    defer {
        switch (ix) {
            .authorize_with_seed => |aws| allocator.free(aws.authority_seed),
            .authorize_checked_with_seed => |acws| allocator.free(acws.authority_seed),
            else => {},
        }
    }

    var result = ObjectMap.init(allocator);
    errdefer result.deinit();

    switch (ix) {
        .initialize => |init| {
            try checkNumStakeAccounts(instruction.accounts, 2);
            const authorized, const lockup = init;
            var info = ObjectMap.init(allocator);
            // authorized object
            var authorized_obj = ObjectMap.init(allocator);
            try authorized_obj.put("staker", try pubkeyToValue(allocator, authorized.staker));
            try authorized_obj.put("withdrawer", try pubkeyToValue(
                allocator,
                authorized.withdrawer,
            ));
            try info.put("authorized", .{ .object = authorized_obj });
            // lockup object
            var lockup_obj = ObjectMap.init(allocator);
            try lockup_obj.put("custodian", try pubkeyToValue(allocator, lockup.custodian));
            try lockup_obj.put("epoch", .{ .integer = @intCast(lockup.epoch) });
            try lockup_obj.put("unixTimestamp", .{ .integer = lockup.unix_timestamp });
            try info.put("lockup", .{ .object = lockup_obj });
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initialize" });
        },
        .authorize => |auth| {
            try checkNumStakeAccounts(instruction.accounts, 3);
            const new_authorized, const authority_type = auth;
            var info = ObjectMap.init(allocator);
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityType", stakeAuthorizeToValue(authority_type));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Optional custodian
            if (instruction.accounts.len >= 4) {
                try info.put("custodian", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[3])).?,
                ));
            }
            try info.put("newAuthority", try pubkeyToValue(allocator, new_authorized));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorize" });
        },
        .delegate_stake => {
            try checkNumStakeAccounts(instruction.accounts, 6);
            var info = ObjectMap.init(allocator);
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try info.put("stakeConfigAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("stakeHistorySysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "delegate" });
        },
        .split => |lamports| {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("newSplitAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "split" });
        },
        .withdraw => |lamports| {
            try checkNumStakeAccounts(instruction.accounts, 5);
            var info = ObjectMap.init(allocator);
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            // Optional custodian
            if (instruction.accounts.len >= 6) {
                try info.put("custodian", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[5])).?,
                ));
            }
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeHistorySysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("withdrawAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "withdraw" });
        },
        .deactivate => {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "deactivate" });
        },
        .set_lockup => |lockup_args| {
            try checkNumStakeAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("custodian", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lockup", try lockupArgsToValue(allocator, lockup_args));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "setLockup" });
        },
        .merge => {
            try checkNumStakeAccounts(instruction.accounts, 5);
            var info = ObjectMap.init(allocator);
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("stakeHistorySysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "merge" });
        },
        .authorize_with_seed => |aws| {
            try checkNumStakeAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("authorityBase", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authorityOwner", try pubkeyToValue(allocator, aws.authority_owner));
            try info.put("authoritySeed", .{ .string = aws.authority_seed });
            try info.put("authorityType", stakeAuthorizeToValue(aws.stake_authorize));
            // Optional clockSysvar
            if (instruction.accounts.len >= 3) {
                try info.put("clockSysvar", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[2])).?,
                ));
            }
            // Optional custodian
            if (instruction.accounts.len >= 4) {
                try info.put("custodian", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[3])).?,
                ));
            }
            try info.put("newAuthorized", try pubkeyToValue(allocator, aws.new_authorized_pubkey));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeWithSeed" });
        },
        .initialize_checked => {
            try checkNumStakeAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("staker", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("withdrawer", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeChecked" });
        },
        .authorize_checked => |authority_type| {
            try checkNumStakeAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("authorityType", stakeAuthorizeToValue(authority_type));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Optional custodian
            if (instruction.accounts.len >= 5) {
                try info.put("custodian", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[4])).?,
                ));
            }
            try info.put("newAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeChecked" });
        },
        .authorize_checked_with_seed => |acws| {
            try checkNumStakeAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("authorityBase", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authorityOwner", try pubkeyToValue(allocator, acws.authority_owner));
            try info.put("authoritySeed", .{ .string = acws.authority_seed });
            try info.put("authorityType", stakeAuthorizeToValue(acws.stake_authorize));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            // Optional custodian
            if (instruction.accounts.len >= 5) {
                try info.put("custodian", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[4])).?,
                ));
            }
            try info.put("newAuthorized", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "authorizeCheckedWithSeed" });
        },
        .set_lockup_checked => |lockup_args| {
            try checkNumStakeAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("custodian", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            var lockup_obj = ObjectMap.init(allocator);
            if (lockup_args.epoch) |epoch| {
                try lockup_obj.put("epoch", .{ .integer = @intCast(epoch) });
            }
            if (lockup_args.unix_timestamp) |ts| {
                try lockup_obj.put("unixTimestamp", .{ .integer = ts });
            }
            // Optional new custodian from account
            if (instruction.accounts.len >= 3) {
                try lockup_obj.put("custodian", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[2])).?,
                ));
            }
            try info.put("lockup", .{ .object = lockup_obj });
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "setLockupChecked" });
        },
        .get_minimum_delegation => {
            const info = ObjectMap.init(allocator);
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "getMinimumDelegation" });
        },
        .deactivate_delinquent => {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("referenceVoteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "deactivateDelinquent" });
        },
        ._redelegate => {
            try checkNumStakeAccounts(instruction.accounts, 5);
            var info = ObjectMap.init(allocator);
            try info.put("newStakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("stakeAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("stakeConfigAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("voteAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "redelegate" });
        },
        .move_stake => |lamports| {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "moveStake" });
        },
        .move_lamports => |lamports| {
            try checkNumStakeAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("lamports", .{ .integer = @intCast(lamports) });
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("stakeAuthority", try pubkeyToValue(
                allocator,
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
fn stakeAuthorizeToValue(auth: stake_program.state.StakeStateV2.StakeAuthorize) JsonValue {
    return .{ .string = switch (auth) {
        .staker => "Staker",
        .withdrawer => "Withdrawer",
    } };
}

/// Convert LockupArgs to a JSON Value object
fn lockupArgsToValue(allocator: Allocator, lockup_args: StakeLockupArgs) !JsonValue {
    var obj = ObjectMap.init(allocator);
    errdefer obj.deinit();

    if (lockup_args.custodian) |custodian| {
        try obj.put("custodian", try pubkeyToValue(allocator, custodian));
    }
    if (lockup_args.epoch) |epoch| {
        try obj.put("epoch", .{ .integer = @intCast(epoch) });
    }
    if (lockup_args.unix_timestamp) |ts| {
        try obj.put("unixTimestamp", .{ .integer = ts });
    }

    return .{ .object = obj };
}

// ============================================================================
// BPF Upgradeable Loader Instruction Parser
// ============================================================================

/// Parse a BPF upgradeable loader instruction into a JSON Value.
fn parseBpfUpgradeableLoaderInstruction(
    allocator: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(
        allocator,
        BpfUpgradeableLoaderInstruction,
        instruction.data,
        .{},
    ) catch {
        return error.DeserializationFailed;
    };
    defer {
        switch (ix) {
            .write => |w| allocator.free(w.bytes),
            else => {},
        }
    }

    var result = ObjectMap.init(allocator);
    errdefer result.deinit();

    switch (ix) {
        .initialize_buffer => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            // Optional authority
            if (instruction.accounts.len > 1) {
                try info.put("authority", try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(instruction.accounts[1])).?,
                ));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeBuffer" });
        },
        .write => |w| {
            try checkNumBpfLoaderAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Base64 encode the bytes
            const base64_encoder = std.base64.standard;
            const encoded_len = base64_encoder.Encoder.calcSize(w.bytes.len);
            const encoded = try allocator.alloc(u8, encoded_len);
            _ = base64_encoder.Encoder.encode(encoded, w.bytes);
            try info.put("bytes", .{ .string = encoded });
            try info.put("offset", .{ .integer = @intCast(w.offset) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "write" });
        },
        .deploy_with_max_data_len => |deploy| {
            try checkNumBpfLoaderAccounts(instruction.accounts, 8);
            var info = ObjectMap.init(allocator);
            try info.put("maxDataLen", .{ .integer = @intCast(deploy.max_data_len) });
            try info.put("payerAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programDataAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("bufferAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[6])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[7])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "deployWithMaxDataLen" });
        },
        .upgrade => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 7);
            var info = ObjectMap.init(allocator);
            try info.put("programDataAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("bufferAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("spillAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("clockSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[6])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "upgrade" });
        },
        .set_authority => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Optional new authority
            if (instruction.accounts.len > 2) {
                if (account_keys.get(@intCast(instruction.accounts[2]))) |new_auth| {
                    try info.put("newAuthority", try pubkeyToValue(allocator, new_auth));
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
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("newAuthority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "setAuthorityChecked" });
        },
        .close => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("recipient", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            // Optional program account
            if (instruction.accounts.len > 3) {
                if (account_keys.get(@intCast(instruction.accounts[3]))) |prog| {
                    try info.put("programAccount", try pubkeyToValue(allocator, prog));
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
            var info = ObjectMap.init(allocator);
            try info.put("additionalBytes", .{ .integer = @intCast(ext.additional_bytes) });
            try info.put("programDataAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            // Optional system program
            if (instruction.accounts.len > 2) {
                if (account_keys.get(@intCast(instruction.accounts[2]))) |sys| {
                    try info.put("systemProgram", try pubkeyToValue(allocator, sys));
                } else {
                    try info.put("systemProgram", .null);
                }
            } else {
                try info.put("systemProgram", .null);
            }
            // Optional payer
            if (instruction.accounts.len > 3) {
                if (account_keys.get(@intCast(instruction.accounts[3]))) |payer| {
                    try info.put("payerAccount", try pubkeyToValue(allocator, payer));
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
            var info = ObjectMap.init(allocator);
            try info.put("programDataAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "migrate" });
        },
        .extend_program_checked => |ext| {
            try checkNumBpfLoaderAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("additionalBytes", .{ .integer = @intCast(ext.additional_bytes) });
            try info.put("programDataAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("programAccount", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("authority", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            // Optional system program
            if (instruction.accounts.len > 3) {
                if (account_keys.get(@intCast(instruction.accounts[3]))) |sys| {
                    try info.put("systemProgram", try pubkeyToValue(allocator, sys));
                } else {
                    try info.put("systemProgram", .null);
                }
            } else {
                try info.put("systemProgram", .null);
            }
            // Optional payer
            if (instruction.accounts.len > 4) {
                if (account_keys.get(@intCast(instruction.accounts[4]))) |payer| {
                    try info.put("payerAccount", try pubkeyToValue(allocator, payer));
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

// ============================================================================
// Shared Helpers
// ============================================================================

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

// ============================================================================
// BPF Loader v2 Instruction Parser
// ============================================================================

/// Parse a BPF Loader v2 instruction into a JSON Value.
fn parseBpfLoaderInstruction(
    allocator: Allocator,
    instruction: sig.ledger.transaction_status.CompiledInstruction,
    account_keys: *const AccountKeys,
) !JsonValue {
    const ix = sig.bincode.readFromSlice(
        allocator,
        BpfLoaderInstruction,
        instruction.data,
        .{},
    ) catch {
        return error.DeserializationFailed;
    };
    defer {
        switch (ix) {
            .write => |w| allocator.free(w.bytes),
            else => {},
        }
    }

    // Validate account keys
    if (instruction.accounts.len == 0 or instruction.accounts[0] >= account_keys.len()) {
        return error.InstructionKeyMismatch;
    }

    var result = ObjectMap.init(allocator);
    errdefer result.deinit();

    switch (ix) {
        .write => |w| {
            try checkNumBpfLoaderAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("offset", .{ .integer = @intCast(w.offset) });
            // Base64 encode the bytes
            const base64_encoder = std.base64.standard;
            const encoded_len = base64_encoder.Encoder.calcSize(w.bytes.len);
            const encoded = try allocator.alloc(u8, encoded_len);
            _ = base64_encoder.Encoder.encode(encoded, w.bytes);
            try info.put("bytes", .{ .string = encoded });
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "write" });
        },
        .finalize => {
            try checkNumBpfLoaderAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "finalize" });
        },
    }

    return .{ .object = result };
}

// ============================================================================
// Associated Token Account Instruction Parser
// ============================================================================

/// Parse an Associated Token Account instruction into a JSON Value.
fn parseAssociatedTokenInstruction(
    allocator: Allocator,
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

    var result = ObjectMap.init(allocator);
    errdefer result.deinit();

    switch (ata_instruction) {
        .create => {
            try checkNumAssociatedTokenAccounts(instruction.accounts, 6);
            var info = ObjectMap.init(allocator);
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("wallet", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("tokenProgram", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "create" });
        },
        .create_idempotent => {
            try checkNumAssociatedTokenAccounts(instruction.accounts, 6);
            var info = ObjectMap.init(allocator);
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("wallet", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("tokenProgram", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createIdempotent" });
        },
        .recover_nested => {
            try checkNumAssociatedTokenAccounts(instruction.accounts, 7);
            var info = ObjectMap.init(allocator);
            try info.put("nestedSource", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nestedMint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("nestedOwner", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try info.put("ownerMint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[4])).?,
            ));
            try info.put("wallet", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[5])).?,
            ));
            try info.put("tokenProgram", try pubkeyToValue(
                allocator,
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

// ============================================================================
// SPL Token Instruction Parser
// ============================================================================

/// SPL Token instruction tag (first byte)
const TokenInstructionTag = enum(u8) {
    InitializeMint = 0,
    InitializeAccount = 1,
    InitializeMultisig = 2,
    Transfer = 3,
    Approve = 4,
    Revoke = 5,
    SetAuthority = 6,
    MintTo = 7,
    Burn = 8,
    CloseAccount = 9,
    FreezeAccount = 10,
    ThawAccount = 11,
    TransferChecked = 12,
    ApproveChecked = 13,
    MintToChecked = 14,
    BurnChecked = 15,
    InitializeAccount2 = 16,
    SyncNative = 17,
    InitializeAccount3 = 18,
    InitializeMultisig2 = 19,
    InitializeMint2 = 20,
    GetAccountDataSize = 21,
    InitializeImmutableOwner = 22,
    AmountToUiAmount = 23,
    UiAmountToAmount = 24,
    InitializeMintCloseAuthority = 25,
    // Extensions start at higher values
    TransferFeeExtension = 26,
    ConfidentialTransferExtension = 27,
    DefaultAccountStateExtension = 28,
    Reallocate = 29,
    MemoTransferExtension = 30,
    CreateNativeMint = 31,
    InitializeNonTransferableMint = 32,
    InterestBearingMintExtension = 33,
    CpiGuardExtension = 34,
    InitializePermanentDelegate = 35,
    TransferHookExtension = 36,
    ConfidentialTransferFeeExtension = 37,
    WithdrawExcessLamports = 38,
    MetadataPointerExtension = 39,
    GroupPointerExtension = 40,
    GroupMemberPointerExtension = 41,
    ConfidentialMintBurnExtension = 42,
    ScaledUiAmountExtension = 43,
    PausableExtension = 44,
    _,
};

/// Authority type for SetAuthority instruction
const TokenAuthorityType = enum(u8) {
    MintTokens = 0,
    FreezeAccount = 1,
    AccountOwner = 2,
    CloseAccount = 3,
    TransferFeeConfig = 4,
    WithheldWithdraw = 5,
    CloseMint = 6,
    InterestRate = 7,
    PermanentDelegate = 8,
    ConfidentialTransferMint = 9,
    TransferHookProgramId = 10,
    ConfidentialTransferFeeConfig = 11,
    MetadataPointer = 12,
    GroupPointer = 13,
    GroupMemberPointer = 14,
    ScaledUiAmount = 15,
    Pause = 16,
    _,

    pub fn toString(self: TokenAuthorityType) []const u8 {
        return switch (self) {
            .MintTokens => "mintTokens",
            .FreezeAccount => "freezeAccount",
            .AccountOwner => "accountOwner",
            .CloseAccount => "closeAccount",
            .TransferFeeConfig => "transferFeeConfig",
            .WithheldWithdraw => "withheldWithdraw",
            .CloseMint => "closeMint",
            .InterestRate => "interestRate",
            .PermanentDelegate => "permanentDelegate",
            .ConfidentialTransferMint => "confidentialTransferMint",
            .TransferHookProgramId => "transferHookProgramId",
            .ConfidentialTransferFeeConfig => "confidentialTransferFeeConfig",
            .MetadataPointer => "metadataPointer",
            .GroupPointer => "groupPointer",
            .GroupMemberPointer => "groupMemberPointer",
            .ScaledUiAmount => "scaledUiAmount",
            .Pause => "pause",
            else => "unknown",
        };
    }

    pub fn getOwnedField(self: TokenAuthorityType) []const u8 {
        return switch (self) {
            .MintTokens,
            .FreezeAccount,
            .TransferFeeConfig,
            .WithheldWithdraw,
            .CloseMint,
            .InterestRate,
            .PermanentDelegate,
            .ConfidentialTransferMint,
            .TransferHookProgramId,
            .ConfidentialTransferFeeConfig,
            .MetadataPointer,
            .GroupPointer,
            .GroupMemberPointer,
            .ScaledUiAmount,
            .Pause,
            => "mint",
            .AccountOwner, .CloseAccount => "account",
            else => "account",
        };
    }
};

/// Parse an SPL Token instruction into a JSON Value.
fn parseTokenInstruction(
    allocator: Allocator,
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

    var result = ObjectMap.init(allocator);
    errdefer result.deinit();

    switch (tag) {
        .InitializeMint => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            if (instruction.data.len < 35) return error.DeserializationFailed;
            const decimals = instruction.data[1];
            const mint_authority = Pubkey{ .data = instruction.data[2..34].* };
            // freeze_authority is optional: 1 byte tag + 32 bytes pubkey
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("decimals", .{ .integer = @intCast(decimals) });
            try info.put("mintAuthority", try pubkeyToValue(allocator, mint_authority));
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            if (instruction.data.len >= 67 and instruction.data[34] == 1) {
                const freeze_authority = Pubkey{ .data = instruction.data[35..67].* };
                try info.put("freezeAuthority", try pubkeyToValue(allocator, freeze_authority));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMint" });
        },
        .InitializeMint2 => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            if (instruction.data.len < 35) return error.DeserializationFailed;
            const decimals = instruction.data[1];
            const mint_authority = Pubkey{ .data = instruction.data[2..34].* };
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("decimals", .{ .integer = @intCast(decimals) });
            try info.put("mintAuthority", try pubkeyToValue(allocator, mint_authority));
            if (instruction.data.len >= 67 and instruction.data[34] == 1) {
                const freeze_authority = Pubkey{ .data = instruction.data[35..67].* };
                try info.put("freezeAuthority", try pubkeyToValue(allocator, freeze_authority));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMint2" });
        },
        .InitializeAccount => {
            try checkNumTokenAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[3])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeAccount" });
        },
        .InitializeAccount2 => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 33) return error.DeserializationFailed;
            const owner = Pubkey{ .data = instruction.data[1..33].* };
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(allocator, owner));
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeAccount2" });
        },
        .InitializeAccount3 => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            if (instruction.data.len < 33) return error.DeserializationFailed;
            const owner = Pubkey{ .data = instruction.data[1..33].* };
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("owner", try pubkeyToValue(allocator, owner));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeAccount3" });
        },
        .InitializeMultisig => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const m = instruction.data[1];
            var info = ObjectMap.init(allocator);
            try info.put("multisig", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("rentSysvar", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            var signers = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(
                allocator,
                instruction.accounts[2..].len,
            );
            for (instruction.accounts[2..]) |signer_idx| {
                try signers.append(try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(signer_idx)).?,
                ));
            }
            try info.put("signers", .{ .array = signers });
            try info.put("m", .{ .integer = @intCast(m) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMultisig" });
        },
        .InitializeMultisig2 => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            if (instruction.data.len < 2) return error.DeserializationFailed;
            const m = instruction.data[1];
            var info = ObjectMap.init(allocator);
            try info.put("multisig", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            var signers = try std.array_list.AlignedManaged(JsonValue, null).initCapacity(
                allocator,
                instruction.accounts[1..].len,
            );
            for (instruction.accounts[1..]) |signer_idx| {
                try signers.append(try pubkeyToValue(
                    allocator,
                    account_keys.get(@intCast(signer_idx)).?,
                ));
            }
            try info.put("signers", .{ .array = signers });
            try info.put("m", .{ .integer = @intCast(m) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMultisig2" });
        },
        .Transfer => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(allocator);
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                allocator,
                "{d}",
                .{amount},
            ) });
            try parseSigners(
                allocator,
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
        .Approve => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(allocator);
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("delegate", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                allocator,
                "{d}",
                .{amount},
            ) });
            try parseSigners(
                allocator,
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
        .Revoke => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            var info = ObjectMap.init(allocator);
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try parseSigners(
                allocator,
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
        .SetAuthority => {
            try checkNumTokenAccounts(instruction.accounts, 2);
            if (instruction.data.len < 3) return error.DeserializationFailed;
            const authority_type = std.meta.intToEnum(
                TokenAuthorityType,
                instruction.data[1],
            ) catch TokenAuthorityType.MintTokens;
            const owned_field = authority_type.getOwnedField();
            var info = ObjectMap.init(allocator);
            try info.put(owned_field, try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("authorityType", .{ .string = authority_type.toString() });
            // new_authority: COption<Pubkey> - 1 byte tag + 32 bytes pubkey
            if (instruction.data.len >= 35 and instruction.data[2] == 1) {
                const new_authority = Pubkey{ .data = instruction.data[3..35].* };
                try info.put("newAuthority", try pubkeyToValue(allocator, new_authority));
            } else {
                try info.put("newAuthority", .null);
            }
            try parseSigners(
                allocator,
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
        .MintTo => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                allocator,
                "{d}",
                .{amount},
            ) });
            try parseSigners(
                allocator,
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
        .Burn => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                allocator,
                "{d}",
                .{amount},
            ) });
            try parseSigners(
                allocator,
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
        .CloseAccount => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try parseSigners(
                allocator,
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
        .FreezeAccount => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try parseSigners(
                allocator,
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
        .ThawAccount => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try parseSigners(
                allocator,
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
        .TransferChecked => {
            try checkNumTokenAccounts(instruction.accounts, 4);
            if (instruction.data.len < 10) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            const decimals = instruction.data[9];
            var info = ObjectMap.init(allocator);
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("tokenAmount", try tokenAmountToUiAmount(allocator, amount, decimals));
            try parseSigners(
                allocator,
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
        .ApproveChecked => {
            try checkNumTokenAccounts(instruction.accounts, 4);
            if (instruction.data.len < 10) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            const decimals = instruction.data[9];
            var info = ObjectMap.init(allocator);
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("delegate", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try info.put("tokenAmount", try tokenAmountToUiAmount(allocator, amount, decimals));
            try parseSigners(
                allocator,
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
        .MintToChecked => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 10) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            const decimals = instruction.data[9];
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("tokenAmount", try tokenAmountToUiAmount(allocator, amount, decimals));
            try parseSigners(
                allocator,
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
        .BurnChecked => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            if (instruction.data.len < 10) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            const decimals = instruction.data[9];
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("tokenAmount", try tokenAmountToUiAmount(allocator, amount, decimals));
            try parseSigners(
                allocator,
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
        .SyncNative => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "syncNative" });
        },
        .GetAccountDataSize => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            // Extension types are in remaining data, but we'll skip detailed parsing for now
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "getAccountDataSize" });
        },
        .InitializeImmutableOwner => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeImmutableOwner" });
        },
        .AmountToUiAmount => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            if (instruction.data.len < 9) return error.DeserializationFailed;
            const amount = std.mem.readInt(u64, instruction.data[1..9], .little);
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("amount", .{ .string = try std.fmt.allocPrint(
                allocator,
                "{d}",
                .{amount},
            ) });
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "amountToUiAmount" });
        },
        .UiAmountToAmount => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            // ui_amount is a string in remaining bytes
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            if (instruction.data.len > 1) {
                try info.put("uiAmount", .{ .string = instruction.data[1..] });
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "uiAmountToAmount" });
        },
        .InitializeMintCloseAuthority => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            // close_authority: COption<Pubkey>
            if (instruction.data.len >= 34 and instruction.data[1] == 1) {
                const close_authority = Pubkey{ .data = instruction.data[2..34].* };
                try info.put("closeAuthority", try pubkeyToValue(allocator, close_authority));
            } else {
                try info.put("closeAuthority", .null);
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeMintCloseAuthority" });
        },
        .CreateNativeMint => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("payer", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("nativeMint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "createNativeMint" });
        },
        .InitializeNonTransferableMint => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializeNonTransferableMint" });
        },
        .InitializePermanentDelegate => {
            try checkNumTokenAccounts(instruction.accounts, 1);
            var info = ObjectMap.init(allocator);
            try info.put("mint", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            if (instruction.data.len >= 33) {
                const delegate = Pubkey{ .data = instruction.data[1..33].* };
                try info.put("delegate", try pubkeyToValue(allocator, delegate));
            }
            try result.put("info", .{ .object = info });
            try result.put("type", .{ .string = "initializePermanentDelegate" });
        },
        .WithdrawExcessLamports => {
            try checkNumTokenAccounts(instruction.accounts, 3);
            var info = ObjectMap.init(allocator);
            try info.put("source", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("destination", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try parseSigners(
                allocator,
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
        .Reallocate => {
            try checkNumTokenAccounts(instruction.accounts, 4);
            var info = ObjectMap.init(allocator);
            try info.put("account", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[0])).?,
            ));
            try info.put("payer", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[1])).?,
            ));
            try info.put("systemProgram", try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(instruction.accounts[2])).?,
            ));
            try parseSigners(
                allocator,
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
        // Extensions that need sub-instruction parsing - return not parsable for now
        .TransferFeeExtension,
        .ConfidentialTransferExtension,
        .DefaultAccountStateExtension,
        .MemoTransferExtension,
        .InterestBearingMintExtension,
        .CpiGuardExtension,
        .TransferHookExtension,
        .ConfidentialTransferFeeExtension,
        .MetadataPointerExtension,
        .GroupPointerExtension,
        .GroupMemberPointerExtension,
        .ConfidentialMintBurnExtension,
        .ScaledUiAmountExtension,
        .PausableExtension,
        => {
            return error.DeserializationFailed;
        },
        _ => {
            return error.DeserializationFailed;
        },
    }

    return .{ .object = result };
}

fn checkNumTokenAccounts(accounts: []const u8, num: usize) !void {
    return checkNumAccounts(accounts, num, .splToken);
}

/// Parse signers for SPL Token instructions.
/// Similar to the Agave implementation's parse_signers function.
fn parseSigners(
    allocator: Allocator,
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
            allocator,
            accounts[last_nonsigner_index + 1 ..].len,
        );
        for (accounts[last_nonsigner_index + 1 ..]) |signer_idx| {
            try signers.append(try pubkeyToValue(
                allocator,
                account_keys.get(@intCast(signer_idx)).?,
            ));
        }
        try info.put(multisig_field_name, try pubkeyToValue(
            allocator,
            account_keys.get(@intCast(accounts[last_nonsigner_index])).?,
        ));
        try info.put("signers", .{ .array = signers });
    } else {
        // Single signer case
        try info.put(owner_field_name, try pubkeyToValue(
            allocator,
            account_keys.get(@intCast(accounts[last_nonsigner_index])).?,
        ));
    }
}

/// Convert token amount to UI amount format matching Agave's token_amount_to_ui_amount_v3.
fn tokenAmountToUiAmount(allocator: Allocator, amount: u64, decimals: u8) !JsonValue {
    var obj = ObjectMap.init(allocator);
    errdefer obj.deinit();

    const amount_str = try std.fmt.allocPrint(allocator, "{d}", .{amount});
    try obj.put("amount", .{ .string = amount_str });
    try obj.put("decimals", .{ .integer = @intCast(decimals) });

    // Calculate UI amount
    if (decimals == 0) {
        const ui_amount_str = try std.fmt.allocPrint(allocator, "{d}", .{amount});
        try obj.put("uiAmount", .{ .number_string = try exactFloat(
            allocator,
            @floatFromInt(amount),
        ) });
        try obj.put("uiAmountString", .{ .string = ui_amount_str });
    } else {
        const divisor: f64 = std.math.pow(f64, 10.0, @floatFromInt(decimals));
        const ui_amount: f64 = @as(f64, @floatFromInt(amount)) / divisor;
        try obj.put("uiAmount", .{ .number_string = try exactFloat(allocator, ui_amount) });
        const ui_amount_str = try sig.runtime.spl_token.realNumberStringTrimmed(
            allocator,
            amount,
            decimals,
        );
        try obj.put("uiAmountString", .{ .string = ui_amount_str });
    }

    return .{ .object = obj };
}

/// Format an f64 as a JSON number string matching Rust's serde_json output.
/// Zig's std.json serializes 3.0 as "3e0", but serde serializes it as "3.0".
fn exactFloat(allocator: Allocator, value: f64) ![]const u8 {
    var buf: [64]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
    // {d} format omits the decimal point for whole numbers (e.g. "3" instead of "3.0").
    // Append ".0" to match serde's behavior of always including a decimal for floats.
    if (std.mem.indexOf(u8, result, ".") == null) {
        return std.fmt.allocPrint(allocator, "{s}.0", .{result});
    }
    return allocator.dupe(u8, result);
}

/// Format a UI amount with the specified number of decimal places.
fn formatUiAmount(allocator: Allocator, value: f64, decimals: u8) ![]const u8 {
    // Format the float value manually with the right precision
    var buf: [64]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return error.FormatError;

    // Find decimal point
    const dot_idx = std.mem.indexOf(u8, result, ".") orelse {
        // No decimal point, add trailing zeros
        var output = try std.ArrayList(u8).initCapacity(allocator, result.len + 1 + decimals);
        errdefer output.deinit(allocator);
        try output.appendSlice(allocator, result);
        try output.append(allocator, '.');
        for (0..decimals) |_| {
            try output.append(allocator, '0');
        }
        return try output.toOwnedSlice(allocator);
    };

    // Has decimal point - pad or truncate to desired precision
    const after_dot = result.len - dot_idx - 1;
    if (after_dot >= decimals) {
        const slice = result[0 .. dot_idx + 1 + decimals];
        var output = try std.ArrayList(u8).initCapacity(
            allocator,
            slice.len,
        );
        errdefer output.deinit(allocator);
        // Truncate
        try output.appendSlice(allocator, slice);
        return try output.toOwnedSlice(allocator);
    } else {
        var output = try std.ArrayList(u8).initCapacity(
            allocator,
            result.len + (decimals - after_dot),
        );
        errdefer output.deinit(allocator);
        // Pad with zeros
        try output.appendSlice(allocator, result);
        for (0..(decimals - after_dot)) |_| {
            try output.append(allocator, '0');
        }
        return try output.toOwnedSlice(allocator);
    }
}

test "ParsableProgram.fromID - known programs" {
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

test "ParsableProgram.fromID - unknown program returns null" {
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

test "ParsableProgram.fromID - spl-memo programs" {
    try std.testing.expectEqual(
        ParsableProgram.splMemo,
        ParsableProgram.fromID(SPL_MEMO_V1_ID).?,
    );
    try std.testing.expectEqual(
        ParsableProgram.splMemo,
        ParsableProgram.fromID(SPL_MEMO_V3_ID).?,
    );
}

test "ParsableProgram.fromID - spl-associated-token-account" {
    try std.testing.expectEqual(
        ParsableProgram.splAssociatedTokenAccount,
        ParsableProgram.fromID(SPL_ASSOCIATED_TOKEN_ACC_ID).?,
    );
}

test "parseMemoInstruction - valid UTF-8" {
    const allocator = std.testing.allocator;
    const result = try parseMemoInstruction(allocator, "hello world");
    defer switch (result) {
        .string => |s| allocator.free(s),
        else => {},
    };
    try std.testing.expectEqualStrings("hello world", result.string);
}

test "parseMemoInstruction - empty data" {
    const allocator = std.testing.allocator;
    const result = try parseMemoInstruction(allocator, "");
    defer switch (result) {
        .string => |s| allocator.free(s),
        else => {},
    };
    try std.testing.expectEqualStrings("", result.string);
}

test "makeUiPartiallyDecodedInstruction" {
    const allocator = std.testing.allocator;
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
    defer {
        allocator.free(result.programId);
        for (result.accounts) |a| allocator.free(a);
        allocator.free(result.accounts);
        allocator.free(result.data);
    }

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

test "parseUiInstruction - unknown program falls back to partially decoded" {
    // Use arena allocator since parse functions allocate many small objects
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
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

test "parseInstruction - system transfer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
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

test "parseInstruction - spl-memo" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
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
