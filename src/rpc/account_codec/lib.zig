/// This module provides encoding and decoding of Solana accounts for RPC responses.
/// Supports `jsonParsed`, `base58`, `base64`, and `base64+zstd` encodings.
const std = @import("std");
const base58 = @import("base58");
const zstd = @import("zstd");
const sig = @import("../../sig.zig");

const parse_address_lookup_table = @import("parse_account_lookup_table.zig");
const parse_bpf_upgradeable_loader = @import("parse_bpf_upgradeable_loader.zig");
const parse_config = @import("parse_config.zig");
const parse_nonce = @import("parse_nonce.zig");
const parse_stake = @import("parse_stake.zig");
const parse_sysvar = @import("parse_sysvar.zig");
const parse_token = @import("parse_token.zig");
const parse_token_extension = @import("parse_token_extension.zig");
const parse_vote = @import("parse_vote.zig");

const Pubkey = sig.core.Pubkey;

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
    jsonParsed: []const u8,

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
            .jsonParsed => |json_str| {
                try jw.beginWriteRaw();
                try jw.writer.writeAll(json_str);
                jw.endWriteRaw();
            },
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
            .object_begin => {
                const val = try std.json.innerParse(std.json.Value, allocator, source, options);
                return .{ .jsonParsed = try std.json.Stringify.valueAlloc(allocator, val, .{}) };
            },
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
    data_slice: ?DataSlice,
) !AccountData {
    // Build additional data for token accounts, fetch mint and clock for Token-2022 responses.
    const additional_data = buildTokenAdditionalData(
        allocator,
        account,
        slot_reader,
    );

    var account_data_iter = account.data.iterator();

    // Try to parse based on owner program
    const maybe_parsed_account = parseAccount(
        allocator,
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
        const json_str = try std.json.Stringify.valueAlloc(
            allocator,
            parsed,
            .{},
        );
        return .{
            .jsonParsed = json_str,
        };
    }

    // Fallback: encode as base64 string when jsonParsed fails.
    // [agave] https://github.com/anza-xyz/agave/blob/8803776abe/rpc/src/rpc.rs#L2504-L2509
    // SPL token accounts ignore data_slice in the fallback path because
    // get_parsed_token_account hardcodes it to None.
    const is_spl_token = sig.runtime.ids.SPL_TOKEN_PROGRAM_ID.equals(&account.owner) or
        sig.runtime.ids.SPL_TOKEN_2022_PROGRAM_ID.equals(&account.owner);
    const fallback_slice = if (is_spl_token) null else data_slice;
    var encoded = try std.ArrayListUnmanaged(u8).initCapacity(
        allocator,
        // If jsonParsed fails, we fallback to base64 encoding, so we need to allocate
        // enough capacity for the encoded string here.
        estimateEncodedSize(account, .base64, fallback_slice),
    );
    errdefer encoded.deinit(allocator);
    try encodeAccountData(allocator, account, .base64, fallback_slice, encoded.writer(allocator));
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
            const base64_writer = base64_ctx.writer();

            // TODO: Implement native std.io.Writer for base64.EncodingStream.WriterCtx
            // to remove use of this adapter and avoid double buffering.
            var adapter_buf: [256]u8 = undefined;
            var adapter = base64_writer.adaptToNewApi(&adapter_buf);

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
                &adapter.new_interface,
                &compressor,
                zstd_out_buf,
            );
            var iter = account.data.iteratorRanged(start, end);

            while (iter.nextFrame()) |frame_slice| {
                try zstd_ctx.writer().writeAll(frame_slice);
            }

            try zstd_ctx.finish();
            try adapter.new_interface.flush();
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

/// Wrapper for f64 values that serializes to JSON matching Rust's ryu formatting
/// used by serde_json in Agave. Ensures whole-number floats include ".0"
/// (e.g., 1.0 instead of 1) for JSON round-trip fidelity.
/// See: https://github.com/dtolnay/ryu/blob/1.0.5/src/pretty/mod.rs#L52-L118
pub const RyuF64 = struct {
    value: f64,

    pub fn init(value: f64) RyuF64 {
        return .{ .value = value };
    }

    pub fn jsonStringify(self: RyuF64, jw: anytype) @TypeOf(jw.*).Error!void {
        var buf: [64]u8 = undefined;
        const formatted = std.fmt.bufPrint(&buf, "{d}", .{self.value}) catch unreachable;
        if (std.mem.indexOfScalar(u8, formatted, '.') == null) {
            buf[formatted.len] = '.';
            buf[formatted.len + 1] = '0';
            try jw.print("{s}", .{buf[0 .. formatted.len + 2]});
        } else {
            try jw.print("{s}", .{formatted});
        }
    }
};

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

/// Wrapper for byte arrays that serialize as JSON strings without base64 encoding.
pub fn JsonString(comptime max_len: usize) type {
    return struct {
        inner: [max_len]u8 = undefined,
        len: usize = 0,

        const Self = @This();

        // stack allocate the buffer and initialize len to 0. The caller can then use appendSliceAssumeCapacity
        pub fn init() Self {
            return .{ .inner = undefined, .len = 0 };
        }

        pub fn fromSlice(slice: []const u8) Self {
            var result = Self{};
            @memcpy(result.inner[0..slice.len], slice);
            result.len = slice.len;
            return result;
        }

        pub fn constSlice(self: *const Self) []const u8 {
            return self.inner[0..self.len];
        }

        pub fn appendSliceAssumeCapacity(self: *Self, items: []const u8) void {
            @memcpy(self.inner[self.len..][0..items.len], items);
            self.len += items.len;
        }

        pub fn appendNTimesAssumeCapacity(self: *Self, value: u8, n: usize) void {
            @memset(self.inner[self.len..][0..n], value);
            self.len += n;
        }

        pub fn jsonStringify(self: Self, jw: anytype) @TypeOf(jw.*).Error!void {
            try jw.write(self.constSlice());
        }
    };
}

/// Wrapper for arrays of items that serialize as JSON arrays.
pub fn JsonArray(comptime T: type, comptime max_len: usize) type {
    return struct {
        inner: [max_len]T = undefined,
        len: usize = 0,

        const Self = @This();

        pub fn get(self: *const Self, index: usize) T {
            return self.inner[index];
        }

        pub fn constSlice(self: *const Self) []const T {
            return self.inner[0..self.len];
        }

        pub fn append(self: *Self, item: T) error{Overflow}!void {
            if (self.len >= max_len) return error.Overflow;
            self.inner[self.len] = item;
            self.len += 1;
        }

        pub fn appendAssumeCapacity(self: *Self, item: T) void {
            std.debug.assert(self.len < max_len);
            self.inner[self.len] = item;
            self.len += 1;
        }

        pub fn jsonStringify(self: Self, jw: anytype) @TypeOf(jw.*).Error!void {
            try jw.write(self.constSlice());
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

pub fn parseAccount(
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

        const result = try parseAccount(
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

        const result = try parseAccount(
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

        const result = try parseAccount(
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
