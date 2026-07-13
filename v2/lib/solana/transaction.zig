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

    /// Enumerates the structural failures returned by `parseTransaction`.
    /// Each variant names one invariant of the on-wire encoding; violating
    /// any means the bytes can't represent a transaction the runtime would
    /// ever accept.
    pub const ParseError = error{
        /// The reader ran out of bytes mid-field. For streamed readers this
        /// means "need more data"; for slice readers it means the payload
        /// is truncated.
        EndOfStream,
        /// `signatures.len == 0` — every transaction must carry at least
        /// the fee payer's signature.
        NoSignatures,
        /// `signatures.len > MAX_SIGNATURES`.
        TooManySignatures,
        /// Version-prefix byte set (`0x80` bit) but the encoded version is
        /// not `0`. Only legacy and v0 are recognised.
        InvalidVersion,
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
        /// The parsed transaction consumed more than `MAX_BYTES` — the
        /// solana packet MTU — from the source.
        TransactionTooLarge,
        /// Two static `account_keys` entries are byte-identical. Solana
        /// rejects these as `AccountLoadedTwice`; agave enforces it in
        /// `validate_account_locks`, firedancer in `fd_chkdup_check`.
        AccountLoadedTwice,
        /// A `short_u16` count contained a non-canonical zero continuation
        /// byte (aliasing).
        AliasEncoding,
        /// A `short_u16` count set the continuation bit on the third byte,
        /// which would require a fourth byte the encoding doesn't have.
        ByteThreeContinues,
        /// A `short_u16` count decoded to a value that overflows `u16`.
        Overflow,
    };

    /// Structural parse of the on-wire transaction encoding, driven by the
    /// caller-supplied byte source. Enforces every framing and cross-field
    /// invariant a well-formed transaction must satisfy and returns the
    /// `Layout` on success. The parse is byte-only: it
    /// walks and skips, it never materialises a typed value; the only
    /// bytes it inspects beyond framing are the 32-byte static account
    /// keys, which it compares pairwise to enforce `AccountLoadedTwice`.
    ///
    /// See `ParseError` for the individual failure modes.
    ///
    /// The `reader` parameter is duck-typed, matching this contract:
    ///
    ///   - fn readByte(self: *Reader) error{EndOfStream}!u8
    ///   - fn readSlice(self: *Reader, out: []u8) error{EndOfStream}!void
    ///   - fn skipBytes(self: *Reader, n: usize) error{EndOfStream}!void
    ///   - fn bytesConsumed(self: *const Reader) usize
    ///
    /// `SliceReader` below is the flat-bytes adapter; the merkle-linked
    /// stream walker in `sig/v2/services/replay.zig` is the other one.
    ///
    /// [firedancer] https://github.com/firedancer-io/firedancer/blob/94ed904053082d7bf20267c3761e56a1f6c5aa3a/src/ballet/txn/fd_txn_parse.c
    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/transaction%40v4.1.1/transaction/src/versioned/mod.rs#L137
    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/message%40v4.1.1/message/src/versions/v0/mod.rs#L116
    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/message%40v4.1.1/message/src/legacy.rs#L140
    pub fn parse(reader: anytype) ParseError!Layout {
        const start = reader.bytesConsumed();

        const sig_cnt = try readShortU16(reader);
        if (sig_cnt < 1) return error.NoSignatures;
        if (sig_cnt > MAX_SIGNATURES) return error.TooManySignatures;

        const signatures_off = reader.bytesConsumed() - start;

        try reader.skipBytes(Signature.SIZE * @as(usize, sig_cnt));

        const message_off = reader.bytesConsumed() - start;

        const first = try reader.readByte();
        const legacy = (first & 0x80) == 0;

        const version: VersionedMessage.VersionByte = if (legacy) .legacy else .v0;

        const num_req_sig: u8 = if (legacy) first else blk: {
            if ((first & 0x7f) != 0) return error.InvalidVersion;
            break :blk try reader.readByte();
        };
        if (sig_cnt != num_req_sig) return error.SignatureCountMismatch;

        const ro_signed: u8 = try reader.readByte();
        const ro_unsigned: u8 = try reader.readByte();
        if (ro_signed >= num_req_sig) return error.FeePayerNotWritable;

        const acct_cnt = try readShortU16(reader);
        if (acct_cnt < num_req_sig) return error.NotEnoughAccountKeys;
        if (acct_cnt > MAX_ACCOUNT_ADDRESSES) return error.TooManyAccountKeys;
        if (@as(usize, num_req_sig) + ro_unsigned > acct_cnt)
            return error.ReadonlyRegionOverflowsAccountKeys;

        const static_keys_off = reader.bytesConsumed() - start;

        // Read each static pubkey and check byte-wise against every
        // earlier one — O(n²), but `acct_cnt ≤ 128` bounds it. Folds in
        // what agave's harness gates via `validate_account_locks` and
        // firedancer's `fd_chkdup_check` (bypass-ALUT mode).
        // NOTE: Consider moving this check to the runtime where ALTs have been resolved.
        // Running here drops invalid transactions earlier in the pipeline, but the condition
        // will be rechecked in the runtime once all ALTs have been resolved. If removed we
        // need to ensure transactions violating this constraint are still rejected by the
        // shred parse harness for conformance.
        var static_keys: [MAX_ACCOUNT_ADDRESSES][32]u8 = undefined;
        for (0..acct_cnt) |i| {
            try reader.readSlice(&static_keys[i]);
            for (0..i) |j| {
                if (std.mem.eql(u8, &static_keys[i], &static_keys[j]))
                    return error.AccountLoadedTwice;
            }
        }

        const recent_blockhash_off = reader.bytesConsumed() - start;

        try reader.skipBytes(Hash.SIZE); // recent_blockhash

        const ix_cnt = try readShortU16(reader);
        if (ix_cnt > MAX_INSTRUCTIONS) return error.TooManyInstructions;
        // Any instruction needs both a fee payer and a program (which
        // can't be the fee payer per `InvalidProgramIdIndex`), so
        // `account_keys` must have at least 2.
        if (ix_cnt > 0 and acct_cnt < 2) return error.MissingProgramAccount;

        const instructions_off = reader.bytesConsumed() - start;

        // Per-instruction: `program_id_index` is a static account but not
        // the fee payer. Track the largest referenced account index for
        // `AccountIndexOutOfBounds` below.
        var max_acct: u8 = 0;
        for (0..ix_cnt) |_| {
            const pid = try reader.readByte();
            if (pid == 0 or pid >= acct_cnt) return error.InvalidProgramIdIndex;
            const ax_cnt = try readShortU16(reader);
            for (0..ax_cnt) |_| max_acct = @max(max_acct, try reader.readByte());
            const data_len = try readShortU16(reader);
            try reader.skipBytes(data_len);
        }

        var address_table_lookups_off = reader.bytesConsumed() - start;

        // v0 ALTs.
        var alt_cnt: u16 = 0;
        var loaded_writable_count: usize = 0;
        var loaded_readonly_count: usize = 0;
        if (!legacy) {
            alt_cnt = try readShortU16(reader);

            if (alt_cnt > V0Message.MAX_ADDR_TABLE_LOOKUPS)
                return error.TooManyAddressTableLookups;

            address_table_lookups_off = reader.bytesConsumed() - start;

            // Subtraction is safe: `acct_cnt` was bounded above.
            const alt_headroom: usize = MAX_ACCOUNT_ADDRESSES - @as(usize, acct_cnt);
            for (0..alt_cnt) |_| {
                try reader.skipBytes(Pubkey.SIZE); // table pubkey

                const w = try readShortU16(reader);
                if (w > alt_headroom) return error.AddressTableLookupOverflow;
                try reader.skipBytes(w);
                const r = try readShortU16(reader);
                if (r > alt_headroom) return error.AddressTableLookupOverflow;
                try reader.skipBytes(r);
                if (w + r < 1) return error.EmptyAddressTableLookup;

                loaded_writable_count += @as(usize, w);
                loaded_readonly_count += @as(usize, r);
            }
        }

        const total_account_count = @as(usize, acct_cnt) +
            loaded_writable_count +
            loaded_readonly_count;

        if (total_account_count > MAX_ACCOUNT_ADDRESSES)
            return error.TooManyTotalAddresses;

        // Every instruction account index must reference either a static
        // account or one of the ALT-loaded accounts. Program indices are
        // not included here because they were already checked against
        // `acct_cnt` above (programs can never come from a lookup table;
        // see https://github.com/solana-labs/solana/issues/25034).
        if (@as(usize, max_acct) >= total_account_count)
            return error.AccountIndexOutOfBounds;

        const consumed = reader.bytesConsumed() - start;
        if (consumed > MAX_BYTES) return error.TransactionTooLarge;

        return .{
            .payload_len = @intCast(consumed),

            .signatures_off = @intCast(signatures_off),

            .message_off = @intCast(message_off),
            .message_len = @intCast(consumed - message_off),

            .static_keys_off = @intCast(static_keys_off),
            .recent_blockhash_off = @intCast(recent_blockhash_off),

            .instructions_off = @intCast(instructions_off),
            .address_table_lookups_off = @intCast(address_table_lookups_off),

            .version = version,

            .signature_count = @intCast(sig_cnt),
            .static_key_count = @intCast(acct_cnt),
            .instruction_count = @intCast(ix_cnt),
            .address_table_lookup_count = @intCast(alt_cnt),

            .loaded_writable_count = @intCast(loaded_writable_count),
            .loaded_readonly_count = @intCast(loaded_readonly_count),

            .num_readonly_signed_accounts = ro_signed,
            .num_readonly_unsigned_accounts = ro_unsigned,
        };
    }

    /// Reusable metadata extracted while structurally validating a serialized
    /// transaction.
    ///
    /// Every offset is relative to the first byte of the transaction.
    ///
    /// This type contains no pointers or slices and can safely be stored in
    /// shared memory. Methods that access serialized fields therefore receive
    /// the transaction's backing storage explicitly.
    ///
    /// offsets to collections point to the first element, after the collection's
    /// shortvec length prefix.
    /// TODO: document the layout of the serialized transaction and how it relates to this struct.
    pub const Layout = extern struct {
        /// Number of serialized transaction bytes.
        payload_len: u16,

        /// First signature byte, after the signature-count shortvec.
        signatures_off: u16,

        /// First byte of the signed message.
        ///
        /// For v0 this includes the version-prefix byte.
        message_off: u16,

        /// Length of the complete signed message.
        message_len: u16,

        /// First static account key, after the account-key-count shortvec.
        static_keys_off: u16,

        /// First byte of the 32-byte recent blockhash.
        recent_blockhash_off: u16,

        /// First serialized instruction, after the instruction-count shortvec.
        instructions_off: u16,

        /// First serialized address-table lookup, after its count shortvec.
        ///
        /// For legacy transactions, the count is zero and this points to the
        /// end of the message.
        address_table_lookups_off: u16,

        version: VersionedMessage.VersionByte,

        signature_count: u8,
        static_key_count: u8,
        instruction_count: u8,
        address_table_lookup_count: u8,

        loaded_writable_count: u8,
        loaded_readonly_count: u8,

        num_readonly_signed_accounts: u8,
        num_readonly_unsigned_accounts: u8,

        // TODO: Do we want padding for cacheline alignment?
    };

    pub const View = struct {
        layout: *const Layout,
        payload: []const u8,

        pub fn header(self: View) MessageHeader {
            return .{
                .num_required_signatures = self.layout.signature_count,
                .num_readonly_signed_accounts = self.layout.num_readonly_signed_accounts,
                .num_readonly_unsigned_accounts = self.layout.num_readonly_unsigned_accounts,
            };
        }

        pub fn loadedAddressCount(self: View) usize {
            return @as(usize, self.layout.loaded_writable_count) +
                @as(usize, self.layout.loaded_readonly_count);
        }

        pub fn totalAccountCount(self: View) usize {
            return @as(usize, self.layout.static_key_count) + self.loadedAddressCount();
        }

        pub fn hasAddressTableLookups(self: View) bool {
            return self.layout.address_table_lookup_count != 0;
        }

        pub fn signatures(self: View) []const Signature {
            const offset: usize = self.layout.signatures_off;
            const count: usize = self.layout.signature_count;
            const byte_len = count * Signature.SIZE;

            std.debug.assert(offset + byte_len <= self.layout.payload_len);
            std.debug.assert(byte_len <= self.payload.len - offset);

            const ptr: [*]const Signature = @ptrCast(self.payload[offset..].ptr);

            return ptr[0..count];
        }

        pub fn messageBytes(self: View) []const u8 {
            const offset: usize = self.layout.message_off;
            const len: usize = self.layout.message_len;

            std.debug.assert(offset <= self.layout.payload_len);
            std.debug.assert(len <= self.payload.len - offset);

            return self.payload[offset..][0..len];
        }

        pub fn staticAccountKeys(self: View) []const Pubkey {
            const offset: usize = self.layout.static_keys_off;
            const count: usize = self.layout.static_key_count;
            const byte_len = count * Pubkey.SIZE;

            std.debug.assert(offset + byte_len <= self.layout.payload_len);
            std.debug.assert(byte_len <= self.payload.len - offset);

            const ptr: [*]const Pubkey = @ptrCast(self.payload[offset..].ptr);

            return ptr[0..count];
        }

        pub fn recentBlockhash(self: View) *const Hash {
            const offset: usize = self.layout.recent_blockhash_off;
            const len: usize = Hash.SIZE;

            std.debug.assert(offset + len <= self.layout.payload_len);
            std.debug.assert(len <= self.payload.len - offset);

            return @ptrCast(self.payload[offset..].ptr);
        }

        pub fn instructions(self: View) CompiledInstructionIter {
            return .{
                .reader = .{
                    .bytes = self.payload,
                    .pos = self.layout.instructions_off,
                },
                .remaining = self.layout.instruction_count,
            };
        }

        pub const CompiledInstructionIter = struct {
            reader: SliceReader,
            remaining: u8,

            pub fn next(
                self: *CompiledInstructionIter,
            ) VersionedTransaction.ParseError!?struct {
                program_id_index: u8,
                account_indexes: []const u8,
                data: []const u8,
            } {
                if (self.remaining == 0) return null;

                const program_id_index = try self.reader.readByte();

                const account_count = try readShortU16(&self.reader);
                const account_indexes = try self.reader.takeBytes(account_count);

                const data_len = try readShortU16(&self.reader);
                const data = try self.reader.takeBytes(data_len);

                self.remaining -= 1;

                return .{
                    .program_id_index = program_id_index,
                    .account_indexes = account_indexes,
                    .data = data,
                };
            }
        };

        pub fn addressTableLookups(self: View) AddressTableLookupIter {
            const offset: usize = self.layout.address_table_lookups_off;

            std.debug.assert(offset <= self.payload.len);

            return .{
                .reader = .{
                    .bytes = self.payload,
                    .pos = offset,
                },
                .remaining = self.layout.address_table_lookup_count,
            };
        }

        pub const AddressTableLookupIter = struct {
            reader: SliceReader,
            remaining: u8,

            pub fn next(
                self: *AddressTableLookupIter,
            ) VersionedTransaction.ParseError!?struct {
                account_key: *const Pubkey,
                writable_indexes: []const u8,
                readonly_indexes: []const u8,
            } {
                if (self.remaining == 0) return null;

                const account_key_bytes =
                    try self.reader.takeBytes(Pubkey.SIZE);
                const account_key: *const Pubkey =
                    @ptrCast(account_key_bytes.ptr);

                const writable_count = try readShortU16(&self.reader);
                const writable_indexes =
                    try self.reader.takeBytes(writable_count);

                const readonly_count = try readShortU16(&self.reader);
                const readonly_indexes =
                    try self.reader.takeBytes(readonly_count);

                self.remaining -= 1;

                return .{
                    .account_key = account_key,
                    .writable_indexes = writable_indexes,
                    .readonly_indexes = readonly_indexes,
                };
            }
        };
    };
};

/// Reads a `short_u16` (compact-u16) count from `reader`, rejecting
/// non-canonical encodings and values that overflow `u16`. Shared between
/// `parseTransaction` and the merkle-linked stream walker in replay.zig,
/// so both agree on framing rejects.
pub fn readShortU16(reader: anytype) VersionedTransaction.ParseError!u16 {
    var val: u32 = 0;
    for (0..3) |nth_byte| {
        const b = try reader.readByte();
        if (b == 0 and nth_byte != 0) return error.AliasEncoding;
        val |= @as(u32, b & 0x7f) << @intCast(nth_byte * 7);
        if (b & 0x80 == 0) return std.math.cast(u16, val) orelse return error.Overflow;
        if (nth_byte == 2) return error.ByteThreeContinues;
    }
    unreachable;
}

/// Flat-slice adapter for `parseTransaction`. Wraps a `[]const u8` and
/// tracks position; `bytesConsumed` returns the current offset.
pub const SliceReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn readByte(self: *SliceReader) error{EndOfStream}!u8 {
        if (self.pos >= self.bytes.len) return error.EndOfStream;
        defer self.pos += 1;
        return self.bytes[self.pos];
    }

    pub fn readSlice(self: *SliceReader, out: []u8) error{EndOfStream}!void {
        if (out.len > self.bytes.len - self.pos) return error.EndOfStream;
        @memcpy(out, self.bytes[self.pos..][0..out.len]);
        self.pos += out.len;
    }

    pub fn skipBytes(self: *SliceReader, n: usize) error{EndOfStream}!void {
        if (n > self.bytes.len - self.pos) return error.EndOfStream;
        self.pos += n;
    }

    pub fn bytesConsumed(self: *const SliceReader) usize {
        return self.pos;
    }

    pub fn takeBytes(
        self: *SliceReader,
        len: usize,
    ) error{EndOfStream}![]const u8 {
        if (len > self.bytes.len - self.pos)
            return error.EndOfStream;

        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }
};

pub const VersionedMessage = union(enum) {
    // first byte & 0x80 == 0
    legacy: LegacyMessage,
    // first byte & 0x80 != 0
    v0: V0Message,

    /// Compact internal representation of the message format.
    ///
    /// Versioned values match the low seven bits of the wire prefix.
    /// Legacy has no numeric wire version, so `0xff` is a Sig internal sentinel for it.
    pub const VersionByte = enum(u8) {
        legacy = 0xff,
        v0 = 0,
    };

    pub fn versionByte(self: *const VersionedMessage) VersionByte {
        return switch (self.*) {
            .legacy => .legacy,
            .v0 => .v0,
        };
    }

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
};

pub const LegacyMessage = struct {
    header: MessageHeader,
    account_keys: bincode.ShortVec(Pubkey),
    recent_blockhash: Hash,
    instructions: bincode.ShortVec(CompiledInstruction),
};

pub const V0Message = struct {
    header: MessageHeader,
    account_keys: bincode.ShortVec(Pubkey),
    recent_blockhash: Hash,
    instructions: bincode.ShortVec(CompiledInstruction),
    address_table_lookups: bincode.ShortVec(AddressLookup),

    /// Inclusive maximum number of address-table-lookup entries.
    pub const MAX_ADDR_TABLE_LOOKUPS: usize = 127;
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
};

pub const AddressLookup = struct {
    account_key: Pubkey,
    writable_indexes: bincode.ShortVec(u8),
    readonly_indexes: bincode.ShortVec(u8),
};

// ---------------------------------------------------------------------------
// Tests for `VersionedTransaction.parseTransaction`.
//
// Each case names the `ParseError` variant it exercises and asserts that
// exact error is returned. The shared `Builder` produces a typed
// `VersionedTransaction`, which is serialised via `bincode.write` and fed
// to `parseTransaction` through a `SliceReader`. Building the typed value
// first lets each test target one field cleanly; the serialised bytes are
// what the parser actually inspects.
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

    /// Serialise this Builder's typed value as `kind` via bincode, then
    /// feed the bytes through `parseTransaction`. Returns the bytes-consumed
    /// count on success.
    fn parse(self: *Builder, kind: std.meta.Tag(VersionedMessage)) !VersionedTransaction.Layout {
        // Enough headroom for every negative test (largest is 129 static
        // keys + 65 empty instructions + a handful of MAX-sized ALTs, all
        // well under 32 KiB).
        var buf: [32 * 1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        try bincode.write(&writer, self.build(kind));
        var reader: SliceReader = .{ .bytes = writer.buffered() };
        return VersionedTransaction.parse(&reader);
    }
};

test "parseTransaction: baseline legacy txn passes" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    _ = try b.parse(.legacy);
}

test "parseTransaction: NoSignatures" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushKeys(1);
    b.header.num_required_signatures = 0;
    try testing.expectError(error.NoSignatures, b.parse(.legacy));
}

test "parseTransaction: TooManySignatures" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(VersionedTransaction.MAX_SIGNATURES + 1);
    try b.pushKeys(VersionedTransaction.MAX_ACCOUNT_ADDRESSES);
    b.header.num_required_signatures = @intCast(VersionedTransaction.MAX_SIGNATURES + 1);
    try testing.expectError(error.TooManySignatures, b.parse(.legacy));
}

test "parseTransaction: SignatureCountMismatch" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    try b.pushSigs(1); // now 2 signatures, header still says 1
    try testing.expectError(error.SignatureCountMismatch, b.parse(.legacy));
}

test "parseTransaction: FeePayerNotWritable" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.header.num_readonly_signed_accounts = 1; // == num_required_signatures
    try testing.expectError(error.FeePayerNotWritable, b.parse(.legacy));
}

test "parseTransaction: NotEnoughAccountKeys" {
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
    try testing.expectError(error.NotEnoughAccountKeys, b.parse(.legacy));
}

test "parseTransaction: TooManyAccountKeys" {
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
    try testing.expectError(error.TooManyAccountKeys, b.parse(.legacy));
}

test "parseTransaction: ReadonlyRegionOverflowsAccountKeys" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.header.num_readonly_unsigned_accounts = 2; // 1 + 2 = 3 > 2
    try testing.expectError(
        error.ReadonlyRegionOverflowsAccountKeys,
        b.parse(.legacy),
    );
}

test "parseTransaction: TooManyInstructions" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    var i: usize = 0;
    while (i < VersionedTransaction.MAX_INSTRUCTIONS) : (i += 1) try b.pushInstr(1, &.{}); // total: 1 baseline + MAX
    try testing.expectError(error.TooManyInstructions, b.parse(.legacy));
}

test "parseTransaction: MissingProgramAccount" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(1);
    b.header.num_readonly_unsigned_accounts = 0;
    try b.pushInstr(0, &.{}); // any pid is invalid here; MissingProgramAccount fires first
    try testing.expectError(error.MissingProgramAccount, b.parse(.legacy));
}

test "parseTransaction: InvalidProgramIdIndex (pid == 0)" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.instructions.items[0].program_id_index = 0;
    try testing.expectError(error.InvalidProgramIdIndex, b.parse(.legacy));
}

test "parseTransaction: InvalidProgramIdIndex (pid >= account_keys.len)" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.instructions.items[0].program_id_index = 2; // account_keys.len == 2
    try testing.expectError(error.InvalidProgramIdIndex, b.parse(.legacy));
}

test "parseTransaction: TooManyAddressTableLookups" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(2);
    try b.pushInstr(1, &.{});
    var i: usize = 0;
    while (i < V0Message.MAX_ADDR_TABLE_LOOKUPS + 1) : (i += 1) try b.pushAlt(&.{0}, &.{});
    try testing.expectError(error.TooManyAddressTableLookups, b.parse(.v0));
}

test "parseTransaction: EmptyAddressTableLookup" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(2);
    try b.pushInstr(1, &.{});
    try b.pushAlt(&.{}, &.{});
    try testing.expectError(error.EmptyAddressTableLookup, b.parse(.v0));
}

test "parseTransaction: AddressTableLookupOverflow" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(2);
    try b.pushInstr(1, &.{});
    // headroom = 128 - 2 = 126; writable.len = 127 trips the per-ALT bound.
    var writable: [127]u8 = undefined;
    @memset(&writable, 0);
    try b.pushAlt(&writable, &.{});
    try testing.expectError(error.AddressTableLookupOverflow, b.parse(.v0));
}

test "parseTransaction: TooManyTotalAddresses" {
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
    try testing.expectError(error.TooManyTotalAddresses, b.parse(.v0));
}

test "parseTransaction: AccountIndexOutOfBounds (no ALT)" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    // Replace the empty accounts slice with one that references index 2
    // (account_keys.len == 2 → max valid index is 1).
    b.allocator.free(b.instructions.items[0].accounts.items);
    const accts = try b.allocator.dupe(u8, &.{2});
    b.instructions.items[0].accounts = .{ .items = accts };
    try testing.expectError(error.AccountIndexOutOfBounds, b.parse(.legacy));
}

test "parseTransaction: instr account index reachable via ALT accepted" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    try b.pushKeys(2);
    // Instruction references index 2 (one past the static keys); ALT adds
    // exactly one writable account, expanding the addressable range to 3.
    try b.pushInstr(1, &.{2});
    try b.pushAlt(&.{0}, &.{});
    _ = try b.parse(.v0);
}

test "parseTransaction: AccountLoadedTwice" {
    var b = try Builder.baselineLegacy(testing.allocator);
    defer b.deinit();
    b.account_keys.items[1] = b.account_keys.items[0]; // duplicate
    try testing.expectError(error.AccountLoadedTwice, b.parse(.legacy));
}

test "parseTransaction: TransactionTooLarge" {
    var b: Builder = .{ .allocator = testing.allocator };
    defer b.deinit();
    try b.pushSigs(1);
    // 128 static keys is at the `MAX_ACCOUNT_ADDRESSES` cap — the largest
    // static count that survives every earlier invariant, and the
    // 32 * 128 = 4096 bytes of pubkey payload already blows past the
    // 1232-byte MTU. No other check fires first.
    try b.pushKeys(128);
    try b.pushInstr(1, &.{});
    try testing.expectError(error.TransactionTooLarge, b.parse(.legacy));
}

test "parseTransaction: InvalidVersion" {
    // Assemble a minimal v0-shaped payload but with the version-prefix
    // byte's low bits != 0, which is neither legacy nor a recognised
    // future version.
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeByte(1); // sig_cnt = 1
    try w.writeAll(&[_]u8{0} ** 64); // one signature
    try w.writeByte(0x81); // version prefix set + version = 1 (unrecognised)
    try w.writeByte(1); // num_required_signatures
    var reader: SliceReader = .{ .bytes = w.buffered() };
    try testing.expectError(error.InvalidVersion, VersionedTransaction.parse(&reader));
}

test "parseTransaction: EndOfStream on truncated payload" {
    // Header says 1 signature but the buffer stops before the signature bytes.
    var buf: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeByte(1); // sig_cnt = 1
    try w.writeAll(&[_]u8{0} ** 4); // only 4 of the 64 signature bytes
    var reader: SliceReader = .{ .bytes = w.buffered() };
    try testing.expectError(error.EndOfStream, VersionedTransaction.parse(&reader));
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
