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
