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
