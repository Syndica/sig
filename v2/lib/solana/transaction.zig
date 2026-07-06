const std = @import("std");
const tracy = @import("tracy");
const lib = @import("../lib.zig");

const bincode = lib.solana.bincode;

const Signature = lib.solana.Signature;
const Pubkey = lib.solana.Pubkey;
const Hash = lib.solana.Hash;

pub const Entry = struct {
    num_hashes: u64,
    hash: Hash,
    transactions: bincode.Vec(VersionedTransaction),

    /// An entry is a "tick" iff it carries no transactions.
    pub fn isTick(self: Entry) bool {
        return self.transactions.items.len == 0;
    }
};

pub const VersionedTransaction = struct {
    signatures: bincode.ShortVec(Signature),
    message: VersionedMessage,

    /// Maximum on-the-wire size of a serialised transaction. Equal to the
    /// Solana packet MTU; the network refuses anything larger.
    pub const MAX_BYTES: usize = 1232;

    /// Inclusive maximum number of signatures per transaction.
    pub const MAX_SIGNATURES: usize = 127;

    /// Inclusive maximum number of static account addresses per transaction
    /// (i.e. excluding ALT-loaded addresses). Matches the bank's
    /// `MAX_TX_ACCOUNT_LOCKS`.
    pub const MAX_ACCOUNT_ADDRESSES: usize = 128;

    /// Inclusive maximum number of top-level instructions per transaction.
    pub const MAX_INSTRUCTIONS: usize = 64;

    /// Total bincode-serialised size in bytes (signatures + message).
    ///
    /// Computed analytically (compact-u16 length prefixes + fixed-size
    /// fields + variable-size payloads) rather than by round-tripping the
    /// structure through `bincode.write`.
    pub fn serializedSize(self: VersionedTransaction) usize {
        var n: usize = 0;
        n += compactU16Len(self.signatures.items.len);
        n += 64 * self.signatures.items.len;
        n += self.message.serializedSize();
        return n;
    }

    /// Returns `true` iff the message's static `account_keys` are pairwise
    /// distinct. Solana rejects transactions whose visible accounts contain
    /// a duplicate (`AccountLoadedTwice`).
    ///
    /// Only the keys carried directly in the message are checked here;
    /// entries resolved from address-lookup tables are invisible without
    /// ALUT resolution and must be re-checked once those are loaded.
    ///
    /// O(n^2); `account_keys.len ≤ 128` by transaction MTU.
    ///
    /// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-rc.1/accounts-db/src/account_locks.rs#L143-L155
    pub fn validateAccountLocks(self: VersionedTransaction) bool {
        const keys = switch (self.message) {
            .legacy => |m| m.account_keys.items,
            .v0 => |m| m.account_keys.items,
        };
        for (0..keys.len - 1) |i| {
            for (i + 1..keys.len) |j| {
                if (std.mem.eql(u8, &keys[i].data, &keys[j].data)) return false;
            }
        }
        return true;
    }

    /// Enumerates the parse-layer structural failures returned by
    /// `sanitize`. Each variant names exactly one invariant that a
    /// well-formed transaction must satisfy; see the doc comment on
    /// `sanitize` for the framing and the checks that are intentionally
    /// left out.
    pub const SanitizeError = error{
        /// `signatures.len == 0` — every transaction must carry at least
        /// the fee payer's signature.
        NoSignatures,
        /// `signatures.len > MAX_SIGNATURES`.
        TooManySignatures,
        /// `signatures.len != header.num_required_signatures` — the outer
        /// signature vector must exactly match the message header.
        SignatureCountMismatch,
        /// `header.num_readonly_signed_accounts >= header.num_required_signatures`
        /// — the fee payer (signer at index 0) must be writable.
        FeePayerNotWritable,
        /// `account_keys.len < header.num_required_signatures` — the
        /// signing region of the account vector is truncated.
        NotEnoughAccountKeys,
        /// `account_keys.len > MAX_ACCOUNT_ADDRESSES`.
        TooManyAccountKeys,
        /// `num_required_signatures + num_readonly_unsigned_accounts > account_keys.len`
        /// — the signing + readonly-unsigned regions overflow the static
        /// account vector.
        ReadonlyRegionOverflowsAccountKeys,
        /// `instructions.len > MAX_INSTRUCTIONS`.
        TooManyInstructions,
        /// `instructions.len > 0` but `account_keys.len < 2` — any
        /// instruction needs both a fee payer and a distinct program
        /// account.
        MissingProgramAccount,
        /// An instruction's `program_id_index` is `0` (would be the fee
        /// payer) or `>= account_keys.len`. Programs cannot come from
        /// address lookup tables, so the check is against the static
        /// account count only.
        InvalidProgramIdIndex,
        /// v0 only: `address_table_lookups.len > V0Message.MAX_ADDR_TABLE_LOOKUPS`.
        TooManyAddressTableLookups,
        /// An address-table-lookup entry has zero writable and zero
        /// readonly indexes — it loads nothing.
        EmptyAddressTableLookup,
        /// An address-table-lookup entry's `writable_indexes.len` or
        /// `readonly_indexes.len` alone exceeds the remaining headroom
        /// `MAX_ACCOUNT_ADDRESSES - account_keys.len`.
        AddressTableLookupOverflow,
        /// `account_keys.len + Σ ALT-loaded > MAX_ACCOUNT_ADDRESSES` — the
        /// combined static + ALT address count exceeds the transaction cap.
        TooManyTotalAddresses,
        /// An instruction references an account index that is beyond the
        /// combined `account_keys.len + Σ ALT-loaded` range.
        AccountIndexOutOfBounds,
    };

    /// Returns success iff the message and signature vector are well-formed
    /// at the parse layer; otherwise returns the specific `SanitizeError`
    /// variant naming the violated invariant.
    ///
    /// Each invariant is a structural constraint of the Solana wire
    /// format: violating it means the bytes can't represent a transaction
    /// the runtime would ever accept — the signature count disagrees with
    /// the header, an instruction's program index points at the fee payer
    /// or off the end of the account vector, ALT bookkeeping overflows
    /// the static caps, etc. Rejecting these here prevents malformed
    /// transactions from reaching account-locking or message resolution
    /// and keeps later stages from having to defend against shapes the
    /// protocol forbids.
    ///
    /// Two related checks are intentionally not part of this method:
    ///
    ///   * MTU (`serializedSize ≤ MAX_BYTES`). Owned by the caller and
    ///     usually enforced at the packet boundary; doing it again here
    ///     would just be defensive.
    ///   * Duplicate static account keys. Owned by `validateAccountLocks`;
    ///     the protocol treats `AccountLoadedTwice` as an account-locking
    ///     concern, not a parse error.
    ///
    /// See `SanitizeError` for the individual failure modes.
    ///
    /// [firedancer] https://github.com/firedancer-io/firedancer/blob/main/src/ballet/txn/fd_txn_parse.c
    /// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-rc.1/transaction-view/src/sanitize.rs
    pub fn sanitize(self: VersionedTransaction) SanitizeError!void {
        // `header`, `account_keys`, and `instructions` are field-identical
        // across both message variants; only ALTs are v0-only.
        const header: MessageHeader, //
        const account_keys: []const Pubkey, //
        const instructions: []const CompiledInstruction //
        = switch (self.message) {
            inline else => |m| .{ m.header, m.account_keys.items, m.instructions.items },
        };
        const address_table_lookups: []const AddressLookup = switch (self.message) {
            .legacy => &.{},
            .v0 => |m| m.address_table_lookups.items,
        };

        const sig_cnt: usize = self.signatures.items.len;
        const acct_cnt: usize = account_keys.len;
        const req_sigs: usize = header.num_required_signatures;
        const ro_signed: usize = header.num_readonly_signed_accounts;
        const ro_unsigned: usize = header.num_readonly_unsigned_accounts;

        if (sig_cnt < 1) return error.NoSignatures;
        if (sig_cnt > MAX_SIGNATURES) return error.TooManySignatures;
        if (sig_cnt != req_sigs) return error.SignatureCountMismatch;
        if (ro_signed >= req_sigs) return error.FeePayerNotWritable;
        if (acct_cnt < req_sigs) return error.NotEnoughAccountKeys;
        if (acct_cnt > MAX_ACCOUNT_ADDRESSES) return error.TooManyAccountKeys;
        if (req_sigs + ro_unsigned > acct_cnt) return error.ReadonlyRegionOverflowsAccountKeys;
        if (instructions.len > MAX_INSTRUCTIONS) return error.TooManyInstructions;

        // Any instruction needs both a fee payer and a program (which
        // can't be the fee payer per `InvalidProgramIdIndex`), so
        // `account_keys` must have at least 2.
        if (instructions.len > 0 and acct_cnt < 2) return error.MissingProgramAccount;

        // Per-instruction: `program_id_index` is a static account but not
        // the fee payer. Also collect the max account index referenced,
        // used for `AccountIndexOutOfBounds` below.
        var max_acct_idx: u8 = 0;
        for (instructions) |ix| {
            const pid: usize = ix.program_id_index;
            if (pid == 0 or pid >= acct_cnt) return error.InvalidProgramIdIndex;
            for (ix.accounts.items) |a| {
                max_acct_idx = @max(max_acct_idx, a);
            }
        }

        if (address_table_lookups.len > V0Message.MAX_ADDR_TABLE_LOOKUPS)
            return error.TooManyAddressTableLookups;

        // Per-ALT bounds + accumulate total ALT-loaded address count for
        // the total-addresses and index-range checks below. Subtraction
        // `MAX_ACCOUNT_ADDRESSES - acct_cnt` is safe since `acct_cnt` was
        // bounded above.
        const alt_headroom: usize = MAX_ACCOUNT_ADDRESSES - acct_cnt;
        var alt_loaded: usize = 0;
        for (address_table_lookups) |alt| {
            const w = alt.writable_indexes.items.len;
            const r = alt.readonly_indexes.items.len;
            if (w + r < 1) return error.EmptyAddressTableLookup;
            if (w > alt_headroom or r > alt_headroom) return error.AddressTableLookupOverflow;
            alt_loaded += w + r;
        }

        if (acct_cnt + alt_loaded > MAX_ACCOUNT_ADDRESSES) return error.TooManyTotalAddresses;

        // Every instruction account index must reference either a static
        // account or one of the ALT-loaded accounts. Program indices are
        // not included here because they were already checked against
        // `acct_cnt` above (programs can never come from a lookup table;
        // see https://github.com/solana-labs/solana/issues/25034).
        if (max_acct_idx >= acct_cnt + alt_loaded) return error.AccountIndexOutOfBounds;
    }
};

pub const VersionedMessage = union(enum) {
    // first byte & 0x80 == 0
    legacy: LegacyMessage,
    // first byte & 0x80 != 0
    v0: V0Message,

    pub fn bincodeRead(
        fba: *std.heap.FixedBufferAllocator,
        reader: *std.Io.Reader,
    ) !VersionedMessage {
        const zone = tracy.Zone.init(@src(), .{ .name = "VersionedMessage.bincodeRead" });
        defer zone.deinit();

        const num_required_signatures: u8, const kind: std.meta.Tag(VersionedMessage) = byte: {
            const first_byte: u8 = try bincode.read(fba, reader, u8);

            if (first_byte & (1 << 7) == 0) {
                break :byte .{ first_byte, .legacy };
            } else {
                const version: u8 = first_byte & 0x7f;
                if (version != 0) return error.InvalidVersion;

                var required_sigs_byte: u8 = undefined;
                try reader.readSliceAll(std.mem.asBytes(&required_sigs_byte));
                break :byte .{ required_sigs_byte, .v0 };
            }
        };

        const header: MessageHeader = .{
            .num_required_signatures = num_required_signatures,
            .num_readonly_signed_accounts = try bincode.read(fba, reader, u8),
            .num_readonly_unsigned_accounts = try bincode.read(fba, reader, u8),
        };

        const account_keys = try bincode.read(fba, reader, bincode.ShortVec(Pubkey));
        const recent_blockhash = try bincode.read(fba, reader, Hash);
        const instructions = try bincode.read(fba, reader, bincode.ShortVec(CompiledInstruction));

        return switch (kind) {
            .legacy => .{
                .legacy = .{
                    .header = header,
                    .account_keys = account_keys,
                    .recent_blockhash = recent_blockhash,
                    .instructions = instructions,
                },
            },
            .v0 => .{
                .v0 = .{
                    .header = header,
                    .account_keys = account_keys,
                    .recent_blockhash = recent_blockhash,
                    .instructions = instructions,
                    .address_table_lookups = try bincode.read(
                        fba,
                        reader,
                        bincode.ShortVec(AddressLookup),
                    ),
                },
            },
        };
    }

    pub fn bincodeWrite(self: *const VersionedMessage, writer: *std.Io.Writer) !void {
        switch (self.*) {
            .legacy => |msg| try bincode.write(writer, msg),
            .v0 => |msg| {
                try writer.writeByte(1 << 7);
                try bincode.write(writer, msg);
            },
        }
    }

    /// Total bincode-serialised size of the message in bytes, including the
    /// `0x80` version-prefix byte for v0 messages.
    pub fn serializedSize(self: VersionedMessage) usize {
        return switch (self) {
            .legacy => |m| m.serializedSize(),
            .v0 => |m| 1 + m.serializedSize(),
        };
    }
};

pub const LegacyMessage = struct {
    header: MessageHeader,
    account_keys: bincode.ShortVec(Pubkey),
    recent_blockhash: Hash,
    instructions: bincode.ShortVec(CompiledInstruction),

    pub fn serializedSize(self: LegacyMessage) usize {
        var n: usize = 3; // MessageHeader (3 u8 fields)
        n += compactU16Len(self.account_keys.items.len) + 32 * self.account_keys.items.len;
        n += 32; // recent_blockhash
        n += compactU16Len(self.instructions.items.len);
        for (self.instructions.items) |ix| n += ix.serializedSize();
        return n;
    }
};

pub const V0Message = struct {
    header: MessageHeader,
    account_keys: bincode.ShortVec(Pubkey),
    recent_blockhash: Hash,
    instructions: bincode.ShortVec(CompiledInstruction),
    address_table_lookups: bincode.ShortVec(AddressLookup),

    /// Inclusive maximum number of address-table-lookup entries.
    pub const MAX_ADDR_TABLE_LOOKUPS: usize = 127;

    /// Size of the v0 message body, *excluding* the `0x80` version-prefix
    /// byte (the prefix is owned by `VersionedMessage.serializedSize`).
    pub fn serializedSize(self: V0Message) usize {
        var n: usize = 3; // MessageHeader
        n += compactU16Len(self.account_keys.items.len) + 32 * self.account_keys.items.len;
        n += 32; // recent_blockhash
        n += compactU16Len(self.instructions.items.len);
        for (self.instructions.items) |ix| n += ix.serializedSize();
        n += compactU16Len(self.address_table_lookups.items.len);
        for (self.address_table_lookups.items) |alt| n += alt.serializedSize();
        return n;
    }
};

pub const MessageHeader = struct {
    num_required_signatures: u8,
    num_readonly_signed_accounts: u8,
    num_readonly_unsigned_accounts: u8,
};

pub const CompiledInstruction = struct {
    program_id_index: u8,
    accounts: bincode.ShortVec(u8),
    data: bincode.ShortVec(u8),

    pub fn serializedSize(self: CompiledInstruction) usize {
        var n: usize = 1; // program_id_index
        n += compactU16Len(self.accounts.items.len) + self.accounts.items.len;
        n += compactU16Len(self.data.items.len) + self.data.items.len;
        return n;
    }
};

pub const AddressLookup = struct {
    account_key: Pubkey,
    writable_indexes: bincode.ShortVec(u8),
    readonly_indexes: bincode.ShortVec(u8),

    pub fn serializedSize(self: AddressLookup) usize {
        var n: usize = 32; // account_key (Pubkey)
        n += compactU16Len(self.writable_indexes.items.len) + self.writable_indexes.items.len;
        n += compactU16Len(self.readonly_indexes.items.len) + self.readonly_indexes.items.len;
        return n;
    }
};

/// Byte length of the compact-u16 (short-vec) length prefix for `n`.
/// Continuation-bit scheme: < 0x80 → 1 byte, < 0x4000 → 2, else 3.
fn compactU16Len(n: usize) usize {
    if (n < 0x80) return 1;
    if (n < 0x4000) return 2;
    return 3;
}

// ---------------------------------------------------------------------------
// Tests for `VersionedTransaction.sanitize`.
//
// Each case names the `SanitizeError` variant it exercises and asserts that
// exact error is returned. The shared `Builder` keeps test bodies focused on
// the single field they are exercising.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Test-only helper that builds in-memory `VersionedTransaction` values
/// without going through bincode. All slices are backed by the test
/// allocator so leaks surface via `testing.allocator`'s assertions.
const Builder = struct {
    allocator: std.mem.Allocator,
    signatures: std.ArrayList(Signature) = .empty,
    header: MessageHeader = .{
        .num_required_signatures = 1,
        .num_readonly_signed_accounts = 0,
        .num_readonly_unsigned_accounts = 1,
    },
    account_keys: std.ArrayList(Pubkey) = .empty,
    instructions: std.ArrayList(CompiledInstruction) = .empty,
    alts: std.ArrayList(AddressLookup) = .empty,

    fn deinit(self: *Builder) void {
        self.signatures.deinit(self.allocator);
        self.account_keys.deinit(self.allocator);
        for (self.instructions.items) |ix| {
            self.allocator.free(ix.accounts.items);
            self.allocator.free(ix.data.items);
        }
        self.instructions.deinit(self.allocator);
        for (self.alts.items) |alt| {
            self.allocator.free(alt.writable_indexes.items);
            self.allocator.free(alt.readonly_indexes.items);
        }
        self.alts.deinit(self.allocator);
    }

    /// Distinct pubkey for index `i`. Last byte = `i`; the rest are zero.
    fn pubkey(i: u8) Pubkey {
        var p: Pubkey = Pubkey.ZEROES;
        p.data[31] = i;
        return p;
    }

    /// Push `n` signatures (zeroed; content doesn't affect sanitize).
    fn pushSigs(self: *Builder, n: usize) !void {
        try self.signatures.appendNTimes(self.allocator, Signature.ZEROES, n);
    }

    /// Push `n` distinct pubkeys.
    fn pushKeys(self: *Builder, n: u8) !void {
        var i: u8 = 0;
        while (i < n) : (i += 1) try self.account_keys.append(self.allocator, pubkey(i));
    }

    fn pushInstr(self: *Builder, program_id_index: u8, accounts: []const u8) !void {
        const accounts_copy = try self.allocator.dupe(u8, accounts);
        errdefer self.allocator.free(accounts_copy);
        try self.instructions.append(self.allocator, .{
            .program_id_index = program_id_index,
            .accounts = .{ .items = accounts_copy },
            .data = .{ .items = &.{} },
        });
    }

    fn pushAlt(self: *Builder, writable: []const u8, readonly: []const u8) !void {
        const w = try self.allocator.dupe(u8, writable);
        errdefer self.allocator.free(w);
        const r = try self.allocator.dupe(u8, readonly);
        errdefer self.allocator.free(r);
        try self.alts.append(self.allocator, .{
            .account_key = pubkey(0xff),
            .writable_indexes = .{ .items = w },
            .readonly_indexes = .{ .items = r },
        });
    }

    fn build(self: *Builder, kind: std.meta.Tag(VersionedMessage)) VersionedTransaction {
        if (kind == .legacy and self.alts.items.len > 0)
            @panic("legacy transaction can't have ALTs");
        const msg: VersionedMessage = switch (kind) {
            .legacy => .{ .legacy = .{
                .header = self.header,
                .account_keys = .{ .items = self.account_keys.items },
                .recent_blockhash = Hash.ZEROES,
                .instructions = .{ .items = self.instructions.items },
            } },
            .v0 => .{ .v0 = .{
                .header = self.header,
                .account_keys = .{ .items = self.account_keys.items },
                .recent_blockhash = Hash.ZEROES,
                .instructions = .{ .items = self.instructions.items },
                .address_table_lookups = .{ .items = self.alts.items },
            } },
        };
        return .{
            .signatures = .{ .items = self.signatures.items },
            .message = msg,
        };
    }

    /// Baseline minimum-valid legacy transaction: 1 sig, fee payer + program,
    /// 1 empty-data instruction. Modify fields after calling this to produce
    /// the negative case under test.
    fn baselineLegacy(allocator: std.mem.Allocator) !Builder {
        var b: Builder = .{ .allocator = allocator };
        errdefer b.deinit();
        try b.pushSigs(1);
        try b.pushKeys(2);
        try b.pushInstr(1, &.{});
        return b;
    }
};

test "sanitize: baseline legacy txn passes" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    try b.build(.legacy).sanitize();
}

test "sanitize: NoSignatures" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushKeys(1);
    b.header.num_required_signatures = 0;
    try testing.expectError(error.NoSignatures, b.build(.legacy).sanitize());
}

test "sanitize: TooManySignatures" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(VersionedTransaction.MAX_SIGNATURES + 1);
    try b.pushKeys(VersionedTransaction.MAX_ACCOUNT_ADDRESSES);
    b.header.num_required_signatures = @intCast(VersionedTransaction.MAX_SIGNATURES + 1);
    try testing.expectError(error.TooManySignatures, b.build(.legacy).sanitize());
}

test "sanitize: SignatureCountMismatch" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    try b.pushSigs(1); // now 2 signatures, header still says 1
    try testing.expectError(error.SignatureCountMismatch, b.build(.legacy).sanitize());
}

test "sanitize: FeePayerNotWritable" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.header.num_readonly_signed_accounts = 1; // == num_required_signatures
    try testing.expectError(error.FeePayerNotWritable, b.build(.legacy).sanitize());
}

test "sanitize: NotEnoughAccountKeys" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    try b.pushSigs(1);
    b.header.num_required_signatures = 2;
    // account_keys still 2, but num_readonly_unsigned=1 means signing+ro_unsigned=3>2
    // would trip `ReadonlyRegionOverflowsAccountKeys`. To isolate this variant, also
    // drop ro_unsigned and shrink keys.
    b.header.num_readonly_unsigned_accounts = 0;
    b.account_keys.items[0] = Builder.pubkey(0);
    b.account_keys.shrinkRetainingCapacity(1);
    // Drop the instruction too (program_id_index=1 would otherwise fail
    // `InvalidProgramIdIndex`).
    b.allocator.free(b.instructions.items[0].accounts.items);
    b.allocator.free(b.instructions.items[0].data.items);
    b.instructions.shrinkRetainingCapacity(0);
    try testing.expectError(error.NotEnoughAccountKeys, b.build(.legacy).sanitize());
}

test "sanitize: TooManyAccountKeys" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    // 129 distinct keys.
    var i: u8 = 0;
    while (i < VersionedTransaction.MAX_ACCOUNT_ADDRESSES + 1) : (i += 1) {
        var p: Pubkey = Pubkey.ZEROES;
        p.data[30] = i / 255;
        p.data[31] = i % 255;
        try b.account_keys.append(b.allocator, p);
    }
    try testing.expectError(error.TooManyAccountKeys, b.build(.legacy).sanitize());
}

test "sanitize: ReadonlyRegionOverflowsAccountKeys" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.header.num_readonly_unsigned_accounts = 2; // 1 + 2 = 3 > 2
    try testing.expectError(error.ReadonlyRegionOverflowsAccountKeys, b.build(.legacy).sanitize());
}

test "sanitize: TooManyInstructions" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    var i: usize = 0;
    while (i < VersionedTransaction.MAX_INSTRUCTIONS) : (i += 1) try b.pushInstr(1, &.{}); // total: 1 baseline + MAX
    try testing.expectError(error.TooManyInstructions, b.build(.legacy).sanitize());
}

test "sanitize: MissingProgramAccount" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(1);
    b.header.num_readonly_unsigned_accounts = 0;
    try b.pushInstr(0, &.{}); // any pid is invalid here; MissingProgramAccount fires first
    try testing.expectError(error.MissingProgramAccount, b.build(.legacy).sanitize());
}

test "sanitize: InvalidProgramIdIndex (pid == 0)" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.instructions.items[0].program_id_index = 0;
    try testing.expectError(error.InvalidProgramIdIndex, b.build(.legacy).sanitize());
}

test "sanitize: InvalidProgramIdIndex (pid >= account_keys.len)" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.instructions.items[0].program_id_index = 2; // account_keys.len == 2
    try testing.expectError(error.InvalidProgramIdIndex, b.build(.legacy).sanitize());
}

test "sanitize: TooManyAddressTableLookups" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(2);
    try b.pushInstr(1, &.{});
    var i: usize = 0;
    while (i < V0Message.MAX_ADDR_TABLE_LOOKUPS + 1) : (i += 1) try b.pushAlt(&.{0}, &.{});
    try testing.expectError(error.TooManyAddressTableLookups, b.build(.v0).sanitize());
}

test "sanitize: EmptyAddressTableLookup" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(2);
    try b.pushInstr(1, &.{});
    try b.pushAlt(&.{}, &.{});
    try testing.expectError(error.EmptyAddressTableLookup, b.build(.v0).sanitize());
}

test "sanitize: AddressTableLookupOverflow" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(2);
    try b.pushInstr(1, &.{});
    // headroom = 128 - 2 = 126; writable.len = 127 trips the per-ALT bound.
    var writable: [127]u8 = undefined;
    @memset(&writable, 0);
    try b.pushAlt(&writable, &.{});
    try testing.expectError(error.AddressTableLookupOverflow, b.build(.v0).sanitize());
}

test "sanitize: TooManyTotalAddresses" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(64);
    b.header.num_readonly_unsigned_accounts = 63;
    try b.pushInstr(1, &.{});
    // headroom per-ALT = 64; pushing two ALTs of 64 each = 128 loaded → 64+128 > 128.
    var slot: [64]u8 = undefined;
    @memset(&slot, 0);
    try b.pushAlt(&slot, &.{});
    try b.pushAlt(&slot, &.{});
    try testing.expectError(error.TooManyTotalAddresses, b.build(.v0).sanitize());
}

test "sanitize: AccountIndexOutOfBounds (no ALT)" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    // Replace the empty accounts slice with one that references index 2
    // (account_keys.len == 2 → max valid index is 1).
    b.allocator.free(b.instructions.items[0].accounts.items);
    const accts = try b.allocator.dupe(u8, &.{2});
    b.instructions.items[0].accounts = .{ .items = accts };
    try testing.expectError(error.AccountIndexOutOfBounds, b.build(.legacy).sanitize());
}

test "sanitize: instr account index reachable via ALT accepted" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(2);
    // Instruction references index 2 (one past the static keys); ALT adds
    // exactly one writable account, expanding the addressable range to 3.
    try b.pushInstr(1, &.{2});
    try b.pushAlt(&.{0}, &.{});
    try b.build(.v0).sanitize();
}

test "sanitize: duplicate account keys are NOT rejected (validateAccountLocks owns that)" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.account_keys.items[1] = b.account_keys.items[0]; // duplicate
    try b.build(.legacy).sanitize();
}

test "VersionedTransaction: bincode round trip" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    const original = b.build(.legacy);

    const original_serialized = blk: {
        var buf: [1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        try bincode.write(&writer, original);
        break :blk writer.buffered();
    };

    try testing.expectEqual(original.serializedSize(), original_serialized.len);

    const decoded = blk: {
        var fba_buf: [4096]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&fba_buf);
        var reader: std.Io.Reader = .fixed(original_serialized);
        break :blk try bincode.read(&fba, &reader, VersionedTransaction);
    };

    const decoded_serialized = blk: {
        var buf: [1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        try bincode.write(&writer, decoded);
        break :blk writer.buffered();
    };

    try testing.expectEqualSlices(u8, original_serialized, decoded_serialized);
}
