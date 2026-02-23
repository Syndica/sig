/// This module provides encoding and decoding of Solana accounts for RPC responses.
/// Supports `jsonParsed`, `base58`, `base64`, and `base64+zstd` encodings.
const std = @import("std");
const sig = @import("../../sig.zig");
const base58 = @import("base58");
const zstd = @import("zstd");
const Pubkey = sig.core.Pubkey;

const parse_vote = @import("parse_vote.zig");
const parse_stake = @import("parse_stake.zig");
const parse_nonce = @import("parse_nonce.zig");
const parse_address_lookup_table = @import("parse_account_lookup_table.zig");
const parse_bpf_upgradeable_loader = @import("parse_bpf_upgradeable_loader.zig");
const parse_sysvar = @import("parse_sysvar.zig");
const parse_config = @import("parse_config.zig");
const parse_token = @import("parse_token.zig");
const parse_token_extension = @import("parse_token_extension.zig");

/// [agave] Maximum input length for base58 encoding.
/// https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/lib.rs#L42
const MAX_BASE58_INPUT_LEN = 128;
const MAX_BASE58_OUTPUT_LEN = base58.encodedMaxSize(MAX_BASE58_INPUT_LEN);

pub const ParseError = error{
    InvalidAccountData,
    OutOfMemory,
};

pub const AccountEncoding = enum {
    /// Legacy, deprecated alias for base58. Retained for RPC backwards compatibility.
    /// Serializes as a plain string instead of the `[data, encoding]` array tuple.
    /// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/lib.rs#L72
    binary,
    base58,
    base64,
    @"base64+zstd",
    jsonParsed,
};

pub const DataSlice = struct {
    offset: usize,
    length: usize,
};

/// The encoded account data returned in RPC responses.
/// Represents the three possible wire formats: a `[data, encoding]` array tuple,
/// a parsed JSON object, or a base64 fallback string when jsonParsed parsing fails.
pub const AccountData = union(enum) {
    encoded: struct { []const u8, AccountEncoding },
    jsonParsed: std.json.Value,

    /// This field is only set when the request object asked for `jsonParsed` encoding,
    /// and the server couldn't find a parser, therefore falling back to returning
    /// the account data in base64 encoding as an array tuple `["data", "base64"]`.
    ///
    /// [Solana documentation REF](https://solana.com/docs/rpc/http/getaccountinfo):
    /// In the drop-down documentation for the encoding field:
    /// > * `jsonParsed` encoding attempts to use program-specific state parsers to
    /// return more human-readable and explicit account state data.
    /// > * If `jsonParsed` is requested but a parser cannot be found, the field falls
    /// back to base64 encoding, detectable when the data field is type string.
    json_parsed_base64_fallback: []const u8,

    /// Legacy binary encoding (deprecated). Serializes as a plain base58-encoded string,
    /// NOT as an `[data, encoding]` array tuple.
    /// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/lib.rs#L39
    legacy_binary: []const u8,

    pub fn jsonStringify(
        self: AccountData,
        /// `*std.json.WriteStream(...)`
        jw: anytype,
    ) @TypeOf(jw.*).Error!void {
        switch (self) {
            .encoded => |pair| try jw.write(pair),
            .jsonParsed => |map| try jw.write(map),
            // Fallback must return array format ["data", "base64"] like testnet
            .json_parsed_base64_fallback => |str| {
                try jw.write(.{ str, AccountEncoding.base64 });
            },
            // Legacy binary: plain string, not an array tuple
            // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/lib.rs#L39
            .legacy_binary => |str| {
                try jw.write(str);
            },
        }
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!AccountData {
        return switch (try source.peekNextTokenType()) {
            .array_begin => .{ .encoded = try std.json.innerParse(
                struct { []const u8, AccountEncoding },
                allocator,
                source,
                options,
            ) },
            .object_begin => .{ .jsonParsed = try std.json.innerParse(
                std.json.Value,
                allocator,
                source,
                options,
            ) },
            .string => .{ .json_parsed_base64_fallback = try std.json.innerParse(
                []const u8,
                allocator,
                source,
                options,
            ) },
            .array_end, .object_end => error.UnexpectedToken,
            else => {
                try source.skipValue();
                return error.UnexpectedToken;
            },
        };
    }
};

/// Handles jsonParsed encoding with fallback to base64.
/// Attempts program-specific parsing; falls back to base64 if no parser is found.
pub fn encodeJsonParsed(
    allocator: std.mem.Allocator,
    pubkey: sig.core.Pubkey,
    account: sig.core.Account,
    slot_reader: sig.accounts_db.SlotAccountReader,
) !AccountData {
    // Build additional data for token accounts, fetch mint and clock for Token-2022 responses.
    const additional_data = buildTokenAdditionalData(
        allocator,
        account,
        slot_reader,
    );

    var account_data_iter = account.data.iterator();
    // Use an arena for parse_account's intermediate allocations (e.g. addresses,
    // votes, epoch_credits, bytecode) which are only needed until JSON serialization
    // is complete.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    // Try to parse based on owner program
    const maybe_parsed_account = parse_account(
        arena.allocator(),
        pubkey,
        account.owner,
        account_data_iter.reader(),
        account.data.len(),
        if (additional_data.spl_token != null) additional_data else null,
    ) catch |err| switch (err) {
        error.InvalidAccountData => null,
        error.OutOfMemory => return error.OutOfMemory,
    };

    if (maybe_parsed_account) |parsed| {
        const json_str = try std.json.stringifyAlloc(
            arena.allocator(),
            parsed,
            .{},
        );
        const json_parsed = try std.json.parseFromSliceLeaky(
            std.json.Value,
            allocator,
            json_str,
            .{},
        );
        return .{
            .jsonParsed = json_parsed,
        };
    }

    // Fallback: encode as base64 string when jsonParsed fails.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/lib.rs#L81-L88
    // When parse_account_data_v3 fails, AGave falls back to base64 encoding.
    var encoded = try std.ArrayListUnmanaged(u8).initCapacity(
        allocator,
        // If jsonParsed fails, we fallback to base64 encoding, so we need to allocate
        // enough capacity for the encoded string here.
        std.base64.standard.Encoder.calcSize(account.data.len()),
    );
    errdefer encoded.deinit(allocator);
    try encodeAccountData(allocator, account, .base64, null, encoded.writer(allocator));
    return .{ .json_parsed_base64_fallback = try encoded.toOwnedSlice(allocator) };
}

/// Handles binary, base58, base64, base64+zstd encodings.
pub fn encodeStandard(
    allocator: std.mem.Allocator,
    account: sig.core.Account,
    encoding: AccountEncoding,
    data_slice: ?DataSlice,
) !AccountData {
    const estimated_size = estimateEncodedSize(account, encoding, data_slice);
    var encoded_data = try std.ArrayListUnmanaged(u8).initCapacity(allocator, estimated_size);
    errdefer encoded_data.deinit(allocator);
    try encodeAccountData(
        allocator,
        account,
        encoding,
        data_slice,
        encoded_data.writer(allocator),
    );
    const slice = try encoded_data.toOwnedSlice(allocator);
    return if (encoding == .binary)
        .{ .legacy_binary = slice }
    else
        .{ .encoded = .{ slice, encoding } };
}

fn estimateEncodedSize(
    account: sig.core.Account,
    encoding: AccountEncoding,
    data_slice: ?DataSlice,
) usize {
    const start, const end = calculateSliceRange(account, data_slice);
    const data_len = end - start;
    return switch (encoding) {
        .binary, .base58 => base58.encodedMaxSize(data_len),
        .base64 => std.base64.standard.Encoder.calcSize(data_len),
        // NOTE: we just use base64 size as a catch-all.
        .@"base64+zstd" => std.base64.standard.Encoder.calcSize(data_len),
        .jsonParsed => unreachable, // should be handled in encodeJsonParsed
    };
}

fn encodeAccountData(
    allocator: std.mem.Allocator,
    account: sig.core.Account,
    encoding: AccountEncoding,
    data_slice: ?DataSlice,
    // std.io.Writer
    writer: anytype,
) !void {
    const start, const end = calculateSliceRange(account, data_slice);
    return switch (encoding) {
        .binary, .base58 => {
            const data_len = end - start;

            if (data_len > MAX_BASE58_INPUT_LEN) {
                // [agave] Returns "error: data too large for bs58 encoding" string instead of error:
                // https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/lib.rs#L44-L47
                // We return an error here since returning a fake "error" string would be misleading.
                return error.Base58DataTooLarge;
            }

            var input_buf: [MAX_BASE58_INPUT_LEN]u8 = undefined;
            var output_buf: [MAX_BASE58_OUTPUT_LEN]u8 = undefined;
            _ = account.data.read(start, input_buf[0..data_len]);
            const encoded_len = base58.Table.BITCOIN.encode(&output_buf, input_buf[0..data_len]);

            try writer.writeAll(output_buf[0..encoded_len]);
        },
        .base64 => {
            var stream = sig.utils.base64.EncodingStream.init(std.base64.standard.Encoder);
            const base64_ctx = stream.writerCtx(writer);
            var iter = account.data.iteratorRanged(start, end);

            while (iter.nextFrame()) |frame_slice| {
                try base64_ctx.writer().writeAll(frame_slice);
            }
            try base64_ctx.flush();
        },
        .@"base64+zstd" => {
            var stream = sig.utils.base64.EncodingStream.init(std.base64.standard.Encoder);
            const base64_ctx = stream.writerCtx(writer);
            const compressor = try zstd.Compressor.init(.{});
            defer compressor.deinit();

            // TODO: recommOutSize is usually 128KiB. We could stack allocate this or re-use
            // buffer set in AccountHookContext instead of allocating it on each call
            // since the server is single-threaded. Unfortunately, the zstd lib's doesn't give us a
            // comptime-known size to use for stack allocation. Instead of assuming, just allocate for now.
            const zstd_out_buf = try allocator.alloc(
                u8,
                zstd.Compressor.recommOutSize(),
            );
            defer allocator.free(zstd_out_buf);
            var zstd_ctx = zstd.writerCtx(
                base64_ctx.writer(),
                &compressor,
                zstd_out_buf,
            );
            var iter = account.data.iteratorRanged(start, end);

            while (iter.nextFrame()) |frame_slice| {
                try zstd_ctx.writer().writeAll(frame_slice);
            }
            try zstd_ctx.finish();
            try base64_ctx.flush();
        },
        .jsonParsed => unreachable, // handled in encodeJsonParsed
    };
}

fn calculateSliceRange(
    account: sig.core.Account,
    data_slice: ?DataSlice,
) struct { u32, u32 } {
    const len = account.data.len();
    const slice_start, const slice_end = blk: {
        const ds = data_slice orelse break :blk .{ 0, len };
        const start = @min(ds.offset, len);
        const end = @min(ds.offset + ds.length, len);
        break :blk .{ start, end };
    };
    return .{ slice_start, slice_end };
}

/// A numeric value that serializes as a JSON string (e.g., "12345") for JavaScript compatibility.
/// JavaScript numbers cannot safely represent values > 2^53, so large integers must be strings.
pub fn Stringified(comptime T: type) type {
    return struct {
        value: T,

        const Self = @This();

        pub fn init(value: T) Self {
            return .{ .value = value };
        }

        pub fn jsonStringify(self: Self, jw: anytype) @TypeOf(jw.*).Error!void {
            try jw.print("\"{d}\"", .{self.value});
        }
    };
}

/// Wrapper for fixed-size byte arrays that serialize as base64 strings.
pub fn Base64Encoded(comptime len: usize) type {
    return struct {
        data: [len]u8,

        const Self = @This();
        const encoded_len = std.base64.standard.Encoder.calcSize(len);

        /// Initialize from a pointer to avoid copying the array.
        pub fn init(data: *const [len]u8) Self {
            return .{ .data = data.* };
        }

        pub fn jsonStringify(self: Self, jw: anytype) @TypeOf(jw.*).Error!void {
            var buf: [encoded_len]u8 = undefined;
            _ = std.base64.standard.Encoder.encode(&buf, &self.data);
            try jw.write(&buf);
        }
    };
}

/// Wrapper for BoundedArray(u8, N) that serializes as a JSON string.
/// BoundedArray by default serializes as {"buffer": ..., "len": N}, but we want just the string.
pub fn JsonString(comptime max_len: usize) type {
    return struct {
        inner: std.BoundedArray(u8, max_len),

        const Self = @This();

        pub fn init(slice: []const u8) Self {
            var result: Self = .{ .inner = .{} };
            result.inner.appendSliceAssumeCapacity(slice);
            return result;
        }

        pub fn fromBounded(bounded: std.BoundedArray(u8, max_len)) Self {
            return .{ .inner = bounded };
        }

        pub fn constSlice(self: *const Self) []const u8 {
            return self.inner.constSlice();
        }

        pub fn jsonStringify(self: Self, jw: anytype) @TypeOf(jw.*).Error!void {
            try jw.write(self.inner.constSlice());
        }
    };
}

/// Wrapper for BoundedArray(T, N) that serializes as a JSON array.
/// BoundedArray by default serializes as {"buffer": ..., "len": N}, but we want just the array.
pub fn JsonArray(comptime T: type, comptime max_len: usize) type {
    return struct {
        inner: std.BoundedArray(T, max_len) = .{},

        const Self = @This();

        pub fn len(self: *const Self) usize {
            return self.inner.len;
        }

        pub fn get(self: *const Self, index: usize) T {
            return self.inner.get(index);
        }

        pub fn constSlice(self: *const Self) []const T {
            return self.inner.constSlice();
        }

        pub fn append(self: *Self, item: T) error{Overflow}!void {
            return self.inner.append(item);
        }

        pub fn appendAssumeCapacity(self: *Self, item: T) void {
            return self.inner.appendAssumeCapacity(item);
        }

        pub fn jsonStringify(self: Self, jw: anytype) @TypeOf(jw.*).Error!void {
            try jw.write(self.inner.constSlice());
        }
    };
}

/// The result of parsing account data for jsonParsed encoding.
/// [agave] https://github.com/anza-xyz/agave/blob/master/account-decoder-client-types/src/lib.rs#L101-L104
pub const ParsedAccount = struct {
    program: []const u8,
    parsed: ParsedContent,
    space: u64,

    pub fn jsonStringify(self: ParsedAccount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("program");
        try jw.write(self.program);
        try jw.objectField("parsed");
        try self.parsed.jsonStringify(jw);
        try jw.objectField("space");
        try jw.write(self.space);
        try jw.endObject();
    }
};

/// Tagged union of all parsable account types.
pub const ParsedContent = union(enum) {
    vote: parse_vote.VoteAccountType,
    stake: parse_stake.StakeAccountType,
    nonce: parse_nonce.NonceAccountType,
    address_lookup_table: parse_address_lookup_table.LookupTableAccountType,
    bpf_upgradeable_loader: parse_bpf_upgradeable_loader.BpfUpgradeableLoaderAccountType,
    sysvar: parse_sysvar.SysvarAccountType,
    config: parse_config.ConfigAccountType,
    token: parse_token.TokenAccountType,

    pub fn jsonStringify(self: ParsedContent, jw: anytype) @TypeOf(jw.*).Error!void {
        switch (self) {
            inline else => |content| try content.jsonStringify(jw),
        }
    }
};

/// Enum of programs that support jsonParsed.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_account_data.rs#L68
const ParsableAccount = enum {
    vote,
    stake,
    nonce,
    address_lookup_table,
    bpf_upgradeable_loader,
    sysvar,
    config,
    token,
    token_2022,

    pub fn fromProgramId(program_id: Pubkey) ?ParsableAccount {
        if (program_id.equals(&sig.runtime.program.vote.ID)) return .vote;
        if (program_id.equals(&sig.runtime.program.stake.ID)) return .stake;
        // Nonce accounts are owned by the system program, so we check the program ID against the system program ID.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_account_data.rs#L36
        if (program_id.equals(&sig.runtime.program.system.ID)) return .nonce;
        if (program_id.equals(&sig.runtime.program.address_lookup_table.ID))
            return .address_lookup_table;
        if (program_id.equals(&sig.runtime.program.bpf_loader.v3.ID)) return .bpf_upgradeable_loader;
        // Sysvar accounts are owned by the sysvar program.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_account_data.rs#L48
        if (program_id.equals(&sig.runtime.sysvar.OWNER_ID)) return .sysvar;
        if (program_id.equals(&sig.runtime.program.config.ID)) return .config;
        if (program_id.equals(&sig.runtime.ids.SPL_TOKEN_PROGRAM_ID)) return .token;
        if (program_id.equals(&sig.runtime.ids.SPL_TOKEN_2022_PROGRAM_ID)) return .token_2022;
        return null;
    }

    pub fn programName(self: ParsableAccount) []const u8 {
        // NOTE: use kebab-case names to match Agave
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_account_data.rs#L67
        // Agave converts enum variant names (e.g. AddressLookupTable) to kebab-case via .to_kebab_case()
        return switch (self) {
            .vote => "vote",
            .stake => "stake",
            .nonce => "nonce",
            .address_lookup_table => "address-lookup-table",
            .bpf_upgradeable_loader => "bpf-upgradeable-loader",
            .sysvar => "sysvar",
            .config => "config",
            .token => "spl-token",
            .token_2022 => "spl-token-2022",
        };
    }
};

/// Additional data needed for parsing certain account types.
/// For SPL Token accounts, this includes mint decimals and interest-bearing/scaled config.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_account_data.rs#L101-L106
pub const AdditionalAccountData = struct {
    spl_token: ?parse_token.SplTokenAdditionalData = null,
};

/// SPL Token Account state enum.
pub const AccountState = enum(u8) {
    uninitialized = 0,
    initialized = 1,
    frozen = 2,
};

pub fn parse_account(
    allocator: std.mem.Allocator,
    pubkey: Pubkey,
    program_id: Pubkey,
    // std.io.Reader
    reader: anytype,
    data_len: u32,
    additional_data: ?AdditionalAccountData,
) ParseError!?ParsedAccount {
    const program = ParsableAccount.fromProgramId(program_id) orelse return null;
    const parsed: ParsedContent = switch (program) {
        .vote => .{ .vote = try parse_vote.parseVote(allocator, reader, pubkey) },
        .stake => .{ .stake = try parse_stake.parseStake(allocator, reader) },
        .nonce => .{ .nonce = try parse_nonce.parseNonce(allocator, reader) },
        .address_lookup_table => .{
            .address_lookup_table = try parse_address_lookup_table.parseAddressLookupTable(
                allocator,
                reader,
                data_len,
            ),
        },
        .bpf_upgradeable_loader => .{
            .bpf_upgradeable_loader = try parse_bpf_upgradeable_loader.parseBpfUpgradeableLoader(
                allocator,
                reader,
                data_len,
            ),
        },
        .sysvar => {
            // Sysvar parsing dispatches by the account's pubkey, not its owner.
            // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L24
            const sysvar_parsed = try parse_sysvar.parseSysvar(
                allocator,
                pubkey,
                reader,
            );
            if (sysvar_parsed) |s| {
                return ParsedAccount{
                    .program = program.programName(),
                    .parsed = .{ .sysvar = s },
                    .space = data_len,
                };
            }
            // Unknown sysvar pubkey - return null to fall back to base64 encoding
            return null;
        },
        .config => {
            const config_parsed = try parse_config.parseConfig(
                allocator,
                pubkey,
                reader,
                data_len,
            );
            if (config_parsed) |c| {
                return ParsedAccount{
                    .program = program.programName(),
                    .parsed = .{ .config = c },
                    .space = data_len,
                };
            }
            // Unknown config account - return null to fall back to base64 encoding
            return null;
        },
        .token, .token_2022 => {
            // Token parsing requires the full data slice.
            const data = try allocator.alloc(u8, data_len);
            defer allocator.free(data);
            const bytes_read = reader.readAll(data) catch return ParseError.InvalidAccountData;
            if (bytes_read != data_len) return ParseError.InvalidAccountData;

            const spl_token_data: ?*const parse_token.SplTokenAdditionalData =
                if (additional_data) |ad| if (ad.spl_token) |*d| d else null else null;
            const token_parsed = try parse_token.parseToken(
                data,
                spl_token_data,
            );
            if (token_parsed) |t| {
                return ParsedAccount{
                    .program = program.programName(),
                    .parsed = .{ .token = t },
                    .space = data_len,
                };
            }
            // Unknown token account - return null to fall back to base64 encoding
            return null;
        },
    };

    return ParsedAccount{
        .program = program.programName(),
        .parsed = parsed,
        .space = data_len,
    };
}

/// Build SplTokenAdditionalData by fetching mint account and Clock syvar.
/// Returns empty additional data if not a token account or fetch fails
pub fn buildTokenAdditionalData(
    allocator: std.mem.Allocator,
    account: sig.core.Account,
    slot_reader: sig.accounts_db.SlotAccountReader,
) AdditionalAccountData {
    // Check if this is a token account
    const is_token_program = account.owner.equals(&sig.runtime.ids.SPL_TOKEN_PROGRAM_ID) or
        account.owner.equals(&sig.runtime.ids.SPL_TOKEN_2022_PROGRAM_ID);
    if (!is_token_program) return .{};

    // Read account data to extract mint pubkey
    var data_iter = account.data.iterator();
    var data_buf: [parse_token.TokenAccount.LEN]u8 = undefined;
    const bytes_read = data_iter.readBytes(&data_buf) catch return .{};
    if (bytes_read < 32) return .{};

    // Extract mint pubkey from token account (first 32 bytes)
    const mint_pubkey = parse_token.getTokenAccountMint(data_buf[0..bytes_read]) orelse return .{};

    // Fetch the mint account
    const maybe_mint_account = slot_reader.get(allocator, mint_pubkey) catch return .{};
    const mint_account = maybe_mint_account orelse return .{};
    defer mint_account.deinit(allocator);

    // Read mint data
    var mint_iter = mint_account.data.iterator();
    const mint_data = allocator.alloc(u8, mint_account.data.len()) catch return .{};
    defer allocator.free(mint_data);
    _ = mint_iter.readBytes(mint_data) catch return .{};

    // Parse mint to get decimals
    const mint = parse_token.Mint.unpack(mint_data) catch return .{};

    // Fetch Clock sysvar for timestamp
    const clock_id = sig.runtime.sysvar.Clock.ID;
    const maybe_clock_account = slot_reader.get(allocator, clock_id) catch return .{};
    const clock_account = maybe_clock_account orelse return .{};
    defer clock_account.deinit(allocator);

    var clock_iter = clock_account.data.iterator();
    const clock = sig.bincode.read(
        allocator,
        sig.runtime.sysvar.Clock,
        clock_iter.reader(),
        .{},
    ) catch return .{};

    // Extract extension configs from mint data
    const InterestCfg = parse_token_extension.InterestBearingConfigData;
    const ScaledCfg = parse_token_extension.ScaledUiAmountConfigData;
    const interest_config = InterestCfg.extractFromMint(mint_data);
    const scaled_config = ScaledCfg.extractFromMint(mint_data);

    return .{
        .spl_token = .{
            .decimals = mint.decimals,
            .unix_timestamp = clock.unix_timestamp,
            .interest_bearing_config = interest_config,
            .scaled_ui_amount_config = scaled_config,
        },
    };
}

// Tests
test "rpc.account_codec.lib: parse account" {
    const allocator = std.testing.allocator;

    // Unknown program returns null
    {
        const unknown_program_id = Pubkey{ .data = [_]u8{99} ** 32 };
        const pubkey = Pubkey{ .data = [_]u8{1} ** 32 };

        const data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
        var stream = std.io.fixedBufferStream(&data);

        const result = try parse_account(
            allocator,
            pubkey,
            unknown_program_id,
            stream.reader(),
            @intCast(data.len),
            null,
        );

        try std.testing.expectEqual(@as(?ParsedAccount, null), result);
    }

    // ParsableAccount.fromProgramId maps known programs
    {
        const prog = sig.runtime.program;
        const ids = sig.runtime.ids;

        // Vote program
        try std.testing.expectEqual(
            ParsableAccount.vote,
            ParsableAccount.fromProgramId(prog.vote.ID).?,
        );
        try std.testing.expectEqualStrings("vote", ParsableAccount.vote.programName());

        // Stake program
        try std.testing.expectEqual(
            ParsableAccount.stake,
            ParsableAccount.fromProgramId(prog.stake.ID).?,
        );
        try std.testing.expectEqualStrings("stake", ParsableAccount.stake.programName());

        // System program (nonce)
        try std.testing.expectEqual(
            ParsableAccount.nonce,
            ParsableAccount.fromProgramId(prog.system.ID).?,
        );
        try std.testing.expectEqualStrings("nonce", ParsableAccount.nonce.programName());

        // Address lookup table
        try std.testing.expectEqual(
            ParsableAccount.address_lookup_table,
            ParsableAccount.fromProgramId(prog.address_lookup_table.ID).?,
        );
        try std.testing.expectEqualStrings(
            "address-lookup-table",
            ParsableAccount.address_lookup_table.programName(),
        );

        // BPF upgradeable loader
        try std.testing.expectEqual(
            ParsableAccount.bpf_upgradeable_loader,
            ParsableAccount.fromProgramId(prog.bpf_loader.v3.ID).?,
        );
        try std.testing.expectEqualStrings(
            "bpf-upgradeable-loader",
            ParsableAccount.bpf_upgradeable_loader.programName(),
        );

        // Sysvar
        try std.testing.expectEqual(
            ParsableAccount.sysvar,
            ParsableAccount.fromProgramId(sig.runtime.sysvar.OWNER_ID).?,
        );
        try std.testing.expectEqualStrings("sysvar", ParsableAccount.sysvar.programName());

        // Config
        try std.testing.expectEqual(
            ParsableAccount.config,
            ParsableAccount.fromProgramId(prog.config.ID).?,
        );
        try std.testing.expectEqualStrings("config", ParsableAccount.config.programName());

        // SPL Token
        try std.testing.expectEqual(
            ParsableAccount.token,
            ParsableAccount.fromProgramId(ids.SPL_TOKEN_PROGRAM_ID).?,
        );
        try std.testing.expectEqualStrings("spl-token", ParsableAccount.token.programName());

        // SPL Token 2022
        try std.testing.expectEqual(
            ParsableAccount.token_2022,
            ParsableAccount.fromProgramId(ids.SPL_TOKEN_2022_PROGRAM_ID).?,
        );
        try std.testing.expectEqualStrings(
            "spl-token-2022",
            ParsableAccount.token_2022.programName(),
        );

        // Unknown program
        const unknown = Pubkey{ .data = [_]u8{255} ** 32 };
        try std.testing.expectEqual(
            @as(?ParsableAccount, null),
            ParsableAccount.fromProgramId(unknown),
        );
    }

    // Parse vote account dispatches correctly
    {
        const vote_pubkey = Pubkey{ .data = [_]u8{1} ** 32 };

        // Use DEFAULT vote state (same pattern as parse_vote tests)
        const vote_state = sig.runtime.program.vote.state.VoteStateV4.DEFAULT;
        const versions = sig.runtime.program.vote.state.VoteStateVersions{ .v4 = vote_state };

        const data = try sig.bincode.writeAlloc(allocator, versions, .{});
        defer allocator.free(data);

        var stream = std.io.fixedBufferStream(data);

        const result = try parse_account(
            allocator,
            vote_pubkey,
            sig.runtime.program.vote.ID,
            stream.reader(),
            @intCast(data.len),
            null,
        );

        try std.testing.expect(result != null);
        try std.testing.expectEqualStrings("vote", result.?.program);
        try std.testing.expectEqual(@as(u64, data.len), result.?.space);

        // Verify it's a vote account - DEFAULT has zeroes for nodePubkey and withdrawer
        switch (result.?.parsed) {
            .vote => |vote_type| {
                switch (vote_type) {
                    .vote => |ui_vote| {
                        try std.testing.expectEqual(Pubkey.ZEROES, ui_vote.nodePubkey);
                        try std.testing.expectEqual(Pubkey.ZEROES, ui_vote.authorizedWithdrawer);
                    },
                }
            },
            else => return error.UnexpectedParsedType,
        }
    }

    // Parse stake account dispatches correctly
    {
        const stake_pubkey = Pubkey{ .data = [_]u8{5} ** 32 };
        const authorized_staker = Pubkey{ .data = [_]u8{6} ** 32 };
        const authorized_withdrawer = Pubkey{ .data = [_]u8{7} ** 32 };

        const StakeStateV2 = sig.runtime.program.stake.StakeStateV2;
        const meta = StakeStateV2.Meta{
            .rent_exempt_reserve = 2282880,
            .authorized = .{
                .staker = authorized_staker,
                .withdrawer = authorized_withdrawer,
            },
            .lockup = .{
                .unix_timestamp = 0,
                .epoch = 0,
                .custodian = Pubkey.ZEROES,
            },
        };

        const stake_state = StakeStateV2{ .initialized = meta };

        const data = try sig.bincode.writeAlloc(allocator, stake_state, .{});
        defer allocator.free(data);

        var stream = std.io.fixedBufferStream(data);

        const result = try parse_account(
            allocator,
            stake_pubkey,
            sig.runtime.program.stake.ID,
            stream.reader(),
            @intCast(data.len),
            null,
        );

        try std.testing.expect(result != null);
        try std.testing.expectEqualStrings("stake", result.?.program);
        try std.testing.expectEqual(@as(u64, data.len), result.?.space);

        // Verify it's a stake account
        switch (result.?.parsed) {
            .stake => |stake_type| {
                switch (stake_type) {
                    .initialized => |ui_stake| {
                        try std.testing.expectEqualStrings(
                            authorized_staker.base58String().constSlice(),
                            ui_stake.meta.authorized.staker.base58String().constSlice(),
                        );
                        try std.testing.expectEqualStrings(
                            authorized_withdrawer.base58String().constSlice(),
                            ui_stake.meta.authorized.withdrawer.base58String().constSlice(),
                        );
                    },
                    else => return error.UnexpectedStakeState,
                }
            },
            else => return error.UnexpectedParsedType,
        }
    }
}
