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
    /// structure through `bincode.write`. This also sidesteps the latent
    /// `VersionedMessage.bincodeWrite` path (a `switch (self)` over a
    /// pointer rather than the tag) which has never been exercised.
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
        var i: usize = 0;
        while (i < keys.len) : (i += 1) {
            var j: usize = i + 1;
            while (j < keys.len) : (j += 1) {
                if (std.mem.eql(u8, &keys[i].data, &keys[j].data)) return false;
            }
        }
        return true;
    }

    /// Returns `true` iff the message and signature vector are well-formed
    /// at the parse layer.
    ///
    /// Each invariant below is a structural constraint of the Solana wire
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
    /// Invariants enforced (numbered for cross-reference with the inline
    /// comments and the tests below):
    ///
    /// | #  | Invariant |
    /// |----|-----------|
    /// |  1 | `1 ≤ signatures.len ≤ MAX_SIGNATURES` |
    /// |  2 | `signatures.len == header.num_required_signatures` |
    /// |  3 | `header.num_readonly_signed < header.num_required_signatures` (the fee payer is writable) |
    /// |  4 | `header.num_required_signatures ≤ account_keys.len ≤ MAX_ACCOUNT_ADDRESSES` |
    /// |  5 | `num_required_signatures + num_readonly_unsigned ≤ account_keys.len` |
    /// |  6 | `instructions.len ≤ MAX_INSTRUCTIONS` |
    /// |  7 | `instructions.len > 0  ⇒  account_keys.len ≥ 2` |
    /// |  8 | per instruction: `0 < program_id_index < account_keys.len` |
    /// |  9 | `address_table_lookups.len ≤ V0Message.MAX_ADDR_TABLE_LOOKUPS` (v0 only) |
    /// | 10 | per ALT: `writable_indexes.len + readonly_indexes.len ≥ 1` |
    /// | 11 | per ALT: each of `writable_indexes.len`, `readonly_indexes.len ≤ MAX_ACCOUNT_ADDRESSES - account_keys.len` |
    /// | 12 | `account_keys.len + Σ ALT-loaded ≤ MAX_ACCOUNT_ADDRESSES` |
    /// | 13 | max account index used by any instruction `< account_keys.len + Σ ALT-loaded` |
    ///
    /// [firedancer] https://github.com/firedancer-io/firedancer/blob/main/src/ballet/txn/fd_txn_parse.c
    /// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-rc.1/transaction-view/src/sanitize.rs
    pub fn sanitize(self: VersionedTransaction) bool {
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

        // (1) signatures.len in [1, MAX_SIGNATURES]
        if (sig_cnt < 1 or sig_cnt > MAX_SIGNATURES) return false;

        // (2) outer signatures vector length must match the message header.
        if (sig_cnt != req_sigs) return false;

        // (3) at least one writable signer (the fee payer).
        if (ro_signed >= req_sigs) return false;

        // (4) account_keys.len in [req_sigs, MAX_ACCOUNT_ADDRESSES].
        if (acct_cnt < req_sigs or acct_cnt > MAX_ACCOUNT_ADDRESSES) return false;

        // (5) signing + readonly-unsigned regions must fit inside account_keys.
        if (req_sigs + ro_unsigned > acct_cnt) return false;

        // (6) instruction count bound.
        if (instructions.len > MAX_INSTRUCTIONS) return false;

        // (7) any instruction needs both a fee payer and a program (which
        // can't be the fee payer per check 8), so account_keys must have at
        // least 2.
        if (instructions.len > 0 and acct_cnt < 2) return false;

        // (8) per-instruction: program_id_index is a static account, but
        // not the fee payer. Also collect the max account index referenced
        // for check 13.
        var max_acct_idx: usize = 0;
        for (instructions) |ix| {
            const pid: usize = ix.program_id_index;
            if (pid == 0 or pid >= acct_cnt) return false;
            for (ix.accounts.items) |a| {
                if (@as(usize, a) > max_acct_idx) max_acct_idx = a;
            }
        }

        // (9) ALT count bound.
        if (address_table_lookups.len > V0Message.MAX_ADDR_TABLE_LOOKUPS) return false;

        // (10) + (11) + accumulate total ALT-loaded address count for
        // checks 12 and 13. Subtraction `MAX_ACCOUNT_ADDRESSES - acct_cnt`
        // is safe since check 4 bounded `acct_cnt`.
        const alt_headroom: usize = MAX_ACCOUNT_ADDRESSES - acct_cnt;
        var alt_loaded: usize = 0;
        for (address_table_lookups) |alt| {
            const w = alt.writable_indexes.items.len;
            const r = alt.readonly_indexes.items.len;
            if (w + r < 1) return false;
            if (w > alt_headroom or r > alt_headroom) return false;
            alt_loaded += w + r;
        }

        // (12) total addressable account count must fit in
        // MAX_ACCOUNT_ADDRESSES.
        if (acct_cnt + alt_loaded > MAX_ACCOUNT_ADDRESSES) return false;

        // (13) every instruction account index must reference either a
        // static account or one of the ALT-loaded accounts. Program indices
        // are not included here because they were already checked against
        // `acct_cnt` in check 8 (programs can never come from a lookup
        // table; see https://github.com/solana-labs/solana/issues/25034).
        if (max_acct_idx >= acct_cnt + alt_loaded) return false;

        return true;
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
        switch (self) {
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
// Each case maps to one of the 13 numbered invariants in the doc-comment
// table on `sanitize`. The shared `Builder` keeps test bodies focused on the
// single field they are exercising.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Test-only helper that builds in-memory `VersionedTransaction` values
/// without going through bincode. All slices are backed by the test
/// allocator so leaks surface via `testing.allocator`'s assertions.
const Builder = struct {
    allocator: std.mem.Allocator,
    signatures: std.ArrayList(Signature) = .{},
    header: MessageHeader = .{
        .num_required_signatures = 1,
        .num_readonly_signed_accounts = 0,
        .num_readonly_unsigned_accounts = 1,
    },
    account_keys: std.ArrayList(Pubkey) = .{},
    instructions: std.ArrayList(CompiledInstruction) = .{},
    alts: std.ArrayList(AddressLookup) = .{},
    is_v0: bool = false,

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
        const data_copy = try self.allocator.alloc(u8, 0);
        try self.instructions.append(self.allocator, .{
            .program_id_index = program_id_index,
            .accounts = .{ .items = accounts_copy },
            .data = .{ .items = data_copy },
        });
    }

    fn pushAlt(self: *Builder, writable: []const u8, readonly: []const u8) !void {
        const w = try self.allocator.dupe(u8, writable);
        const r = try self.allocator.dupe(u8, readonly);
        try self.alts.append(self.allocator, .{
            .account_key = pubkey(0xff),
            .writable_indexes = .{ .items = w },
            .readonly_indexes = .{ .items = r },
        });
    }

    fn build(self: *Builder) VersionedTransaction {
        const msg: VersionedMessage = if (self.is_v0) .{ .v0 = .{
            .header = self.header,
            .account_keys = .{ .items = self.account_keys.items },
            .recent_blockhash = Hash.ZEROES,
            .instructions = .{ .items = self.instructions.items },
            .address_table_lookups = .{ .items = self.alts.items },
        } } else .{ .legacy = .{
            .header = self.header,
            .account_keys = .{ .items = self.account_keys.items },
            .recent_blockhash = Hash.ZEROES,
            .instructions = .{ .items = self.instructions.items },
        } };
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
    try testing.expect(b.build().sanitize());
}

test "sanitize (1): empty signatures rejected" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushKeys(1);
    b.header.num_required_signatures = 0;
    try testing.expect(!b.build().sanitize());
}

test "sanitize (1): >MAX_SIGNATURES rejected" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(VersionedTransaction.MAX_SIGNATURES + 1);
    try b.pushKeys(VersionedTransaction.MAX_ACCOUNT_ADDRESSES);
    b.header.num_required_signatures = @intCast(VersionedTransaction.MAX_SIGNATURES + 1);
    try testing.expect(!b.build().sanitize());
}

test "sanitize (2): sig count != header.num_required_signatures rejected" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    try b.pushSigs(1); // now 2 signatures, header still says 1
    try testing.expect(!b.build().sanitize());
}

test "sanitize (3): fee payer must be writable" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.header.num_readonly_signed_accounts = 1; // == num_required_signatures
    try testing.expect(!b.build().sanitize());
}

test "sanitize (4): account_keys < num_required_signatures rejected" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    try b.pushSigs(1);
    b.header.num_required_signatures = 2;
    // account_keys still 2, but num_readonly_unsigned=1 means signing+ro_unsigned=3>2 → check 5
    // To isolate check 4, also drop ro_unsigned and shrink keys.
    b.header.num_readonly_unsigned_accounts = 0;
    b.account_keys.items[0] = Builder.pubkey(0);
    b.account_keys.shrinkRetainingCapacity(1);
    // Drop the instruction too (program_id_index=1 would otherwise fail check 8).
    b.allocator.free(b.instructions.items[0].accounts.items);
    b.allocator.free(b.instructions.items[0].data.items);
    b.instructions.shrinkRetainingCapacity(0);
    try testing.expect(!b.build().sanitize());
}

test "sanitize (4): account_keys > MAX_ACCOUNT_ADDRESSES rejected" {
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
    try testing.expect(!b.build().sanitize());
}

test "sanitize (5): num_required_signatures + ro_unsigned > account_keys rejected" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.header.num_readonly_unsigned_accounts = 2; // 1 + 2 = 3 > 2
    try testing.expect(!b.build().sanitize());
}

test "sanitize (6): >MAX_INSTRUCTIONS rejected" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    var i: usize = 0;
    while (i < VersionedTransaction.MAX_INSTRUCTIONS) : (i += 1) try b.pushInstr(1, &.{}); // total: 1 baseline + MAX
    try testing.expect(!b.build().sanitize());
}

test "sanitize (7): instructions present but only 1 account_key rejected" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(1);
    b.header.num_readonly_unsigned_accounts = 0;
    try b.pushInstr(0, &.{}); // any pid is invalid here; will trip check 7 first
    try testing.expect(!b.build().sanitize());
}

test "sanitize (8): program_id_index == 0 rejected" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.instructions.items[0].program_id_index = 0;
    try testing.expect(!b.build().sanitize());
}

test "sanitize (8): program_id_index >= account_keys.len rejected" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.instructions.items[0].program_id_index = 2; // account_keys.len == 2
    try testing.expect(!b.build().sanitize());
}

test "sanitize (9): too many address_table_lookups rejected" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    b.is_v0 = true;
    try b.pushSigs(1);
    try b.pushKeys(2);
    try b.pushInstr(1, &.{});
    var i: usize = 0;
    while (i < V0Message.MAX_ADDR_TABLE_LOOKUPS + 1) : (i += 1) try b.pushAlt(&.{0}, &.{});
    try testing.expect(!b.build().sanitize());
}

test "sanitize (10): empty ALT (no writable & no readonly) rejected" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    b.is_v0 = true;
    try b.pushSigs(1);
    try b.pushKeys(2);
    try b.pushInstr(1, &.{});
    try b.pushAlt(&.{}, &.{});
    try testing.expect(!b.build().sanitize());
}

test "sanitize (11): per-ALT writable exceeds headroom rejected" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    b.is_v0 = true;
    try b.pushSigs(1);
    try b.pushKeys(2);
    try b.pushInstr(1, &.{});
    // headroom = 128 - 2 = 126; writable.len = 127 trips check 11.
    var writable: [127]u8 = undefined;
    @memset(&writable, 0);
    try b.pushAlt(&writable, &.{});
    try testing.expect(!b.build().sanitize());
}

test "sanitize (12): total addressable accounts > MAX_ACCOUNT_ADDRESSES rejected" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    b.is_v0 = true;
    try b.pushSigs(1);
    try b.pushKeys(64);
    b.header.num_readonly_unsigned_accounts = 63;
    try b.pushInstr(1, &.{});
    // headroom per-ALT = 64; pushing two ALTs of 64 each = 128 loaded → 64+128 > 128.
    var slot: [64]u8 = undefined;
    @memset(&slot, 0);
    try b.pushAlt(&slot, &.{});
    try b.pushAlt(&slot, &.{});
    try testing.expect(!b.build().sanitize());
}

test "sanitize (13): instr account index out of range (no ALT) rejected" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    // Replace the empty accounts slice with one that references index 2
    // (account_keys.len == 2 → max valid index is 1).
    b.allocator.free(b.instructions.items[0].accounts.items);
    const accts = try b.allocator.dupe(u8, &.{2});
    b.instructions.items[0].accounts = .{ .items = accts };
    try testing.expect(!b.build().sanitize());
}

test "sanitize (13): instr account index reachable via ALT accepted" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    b.is_v0 = true;
    try b.pushSigs(1);
    try b.pushKeys(2);
    // Instruction references index 2 (one past the static keys); ALT adds
    // exactly one writable account, expanding the addressable range to 3.
    try b.pushInstr(1, &.{2});
    try b.pushAlt(&.{0}, &.{});
    try testing.expect(b.build().sanitize());
}

test "sanitize: duplicate account keys are NOT rejected (validateAccountLocks owns that)" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.account_keys.items[1] = b.account_keys.items[0]; // duplicate
    try testing.expect(b.build().sanitize());
}
