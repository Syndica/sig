const Transaction = @This();

const std = @import("std");
const sig = @import("../sig.zig");

const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Writer = sig.io.Writer;
const Reader = sig.io.Reader;
const CompactU16 = sig.bincode.CompactU16;

/// MAX_BYTES is the maximum size of a transaction.
const MAX_BYTES: u32 = 1232;

/// MAX_SIGNATURES is the maximum number of signatures that can be applied to a transaction.
const MAX_SIGNATURES: u8 = 127;

/// MAX_ACCOUNTS is the maximum number of accounts that can be loaded by a transaction.
const MAX_ACCOUNTS: u16 = 128;

/// MAX_INSTRUCTIONS is the maximum number of instructions that can be executed by a transaction.
const MAX_INSTRUCTIONS: u8 = 64;

/// MAX_ADDRESS_LOOKUP_TABLES is the maximum number of address lookup tables that can be used by a transaction.
const MAX_ADDRESS_LOOKUP_TABLES: u16 = 127;

/// VERSION_PREFIX is the first byte of the transaction header that indicates the version.
const VERSION_PREFIX: u8 = 0x80;

/// Signatures
signatures: []const Signature,

/// The message version, either legacy or v0.
version: Version,

/// Signatures for the transaction.
signature_count: u8,
readonly_signed_count: u8,
readonly_unsigned_count: u8,

/// List of accounts loaded by this transaction.
account_ids: []const Pubkey,

/// The blockhash of a recent block.
recent_blockhash: Hash,

/// Instructions that invoke a designated program, are executed in sequence,
/// and committed in one atomic transaction if all succeed.
///
/// # Notes
///
/// Program indexes must index into the list of message `account_addresss` because
/// program id's cannot be dynamically loaded from a lookup table.
///
/// Account indexes must index into the list of addresses
/// constructed from the concatenation of three key lists:
///   1) message `account_addresss`
///   2) ordered list of keys loaded from `writable` lookup table indexes
///   3) ordered list of keys loaded from `readable` lookup table indexes
instructions: []const Instruction,

/// List of address lookup tables used to load additional accounts
/// for this transaction.
maybe_address_lookup_tables: ?[]const AddressLookupTable,

const Version = enum(u8) {
    /// Legacy transaction without address lookup tables.
    Legacy = 0xFF,
    /// Transaction with address lookup tables.
    V0 = 0x00,
};

const Instruction = struct {
    /// Index into the transaction accounts array indicating the program account that executes this instruction.
    program_id_index: u8,
    /// Ordered indices into the transaction accounts array indicating which accounts to pass to the program.
    accounts: []const u8,
    /// The program input data.
    data: []const u8,

    pub fn serialize(self: *const Instruction, writer: anytype) !void {
        try writer.writeByte(self.program_id_index);
        try CompactU16.serialize(writer, @truncate(self.accounts.len)); // WARN: Truncate okay if transaction is valid
        try writer.writeBytes(self.accounts);
        try CompactU16.serialize(writer, @truncate(self.data.len)); // WARN: Truncate okay if transaction is valid
        try writer.writeBytes(self.data);
    }

    pub fn deserialize(reader: anytype) !Instruction {
        const program_id_index = try reader.readByte();
        const accounts_len = try CompactU16.deserialize(reader);
        const accounts = try reader.readBytes(accounts_len);
        const data_len = try CompactU16.deserialize(reader);
        const data = try reader.readBytes(data_len);
        return .{
            .program_id_index = program_id_index,
            .accounts = accounts,
            .data = data,
        };
    }
};

const AddressLookupTable = struct {
    /// Address lookup table account
    account_address: Pubkey,
    /// List of indexes used to load writable account addresses
    writable_indexes: []const u8,
    /// List of indexes used to load readonly account addresses
    readonly_indexes: []const u8,

    pub fn serialize(self: *const AddressLookupTable, writer: anytype) !void {
        try writer.writeBytes(&self.account_address.data);
        try CompactU16.serialize(writer, @truncate(self.writable_indexes.len));
        try writer.writeBytes(self.writable_indexes);
        try CompactU16.serialize(writer, @truncate(self.readonly_indexes.len));
        try writer.writeBytes(self.readonly_indexes);
    }

    pub fn deserialize(reader: anytype) !AddressLookupTable {
        const account_address = .{ .data = (try reader.readBytes(Pubkey.size))[0..Pubkey.size].* };
        const writable_indexes_len = try CompactU16.deserialize(reader);
        const writable_indexes = try reader.readBytes(writable_indexes_len);
        const readonly_indexes_len = try CompactU16.deserialize(reader);
        const readonly_indexes = try reader.readBytes(readonly_indexes_len);
        return .{
            .account_address = account_address,
            .writable_indexes = writable_indexes,
            .readonly_indexes = readonly_indexes,
        };
    }
};

pub fn buildTransferTansaction(
    allocator: std.mem.Allocator,
    random: std.Random,
    from_keypair: KeyPair,
    to_pubkey: Pubkey,
    lamports: u64,
    recent_blockhash: Hash,
) !Transaction {
    _ = allocator;
    _ = random;
    _ = from_keypair;
    _ = to_pubkey;
    _ = lamports;
    _ = recent_blockhash;
    @panic("Not implemented!");
}

/// Only array lists are allocated, underlying data is not copied.
/// The caller must ensure the data is valid for the lifetime of the transaction.
pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
    allocator.free(self.signatures);
    allocator.free(self.account_ids);
    allocator.free(self.instructions);
    if (self.maybe_address_lookup_tables) |addresss_lookup_tables| {
        allocator.free(addresss_lookup_tables);
    }
}

pub fn sanitize(self: Transaction) !void {
    // TODO: Implement
    _ = self;
}

/// Write a transaction to a slice of bytes.
/// Assumes the transaction is valid.
pub fn writeToSlice(self: Transaction, buffer: []u8) ![]u8 {
    var writer = sig.io.Writer.init(buffer);
    try self.serialize(&writer);
    return writer.bytesWritten();
}

/// Read a transaction from a slice of bytes.
/// Returns an error if the transaction is invalid.
pub fn readFromSlice(allocator: std.mem.Allocator, slice: []const u8) !Transaction {
    var reader = Reader.init(slice);
    return try Transaction.deserialize(allocator, &reader);
}

/// Serialize a transaction to a slice of bytes.
/// Assumes the transaction is valid.
pub fn serialize(self: Transaction, writer: anytype) !void {
    // Write signatures slice
    try writer.writeByte(@truncate(self.signatures.len)); // WARN: Truncate okay if transaction is valid
    for (self.signatures) |signature| {
        try writer.writeBytes(&signature.data);
    }

    // Write version prefix
    if (self.version != Version.Legacy) {
        try writer.writeByte(VERSION_PREFIX); // TODO: Correct this, VERSION_PREFIX is not a valid version
    }

    // Serialise the feilds of the transaction which are signed
    try self.serializeSigned(writer);
}

/// Serialize the signed fields of a transaction.
/// Assumes the transaction is valid.
pub fn serializeSigned(self: Transaction, writer: anytype) !void {
    // Write signature counts
    try writer.writeByte(self.signature_count);
    try writer.writeByte(self.readonly_signed_count);
    try writer.writeByte(self.readonly_unsigned_count);

    // Write of account addresses slice
    try CompactU16.serialize(writer, @truncate(self.account_ids.len)); // WARN: Truncate okay if transaction is valid
    for (self.account_ids) |account_address| {
        try writer.writeBytes(&account_address.data);
    }

    // Write recent blockhash
    try writer.writeBytes(&self.recent_blockhash.data);

    // Write instructions slice
    try CompactU16.serialize(writer, @truncate(self.instructions.len)); // WARN: Truncate okay if transaction is valid
    for (self.instructions) |instruction| {
        try instruction.serialize(writer);
    }

    // Write address lookup tables slice
    if (self.maybe_address_lookup_tables) |address_lookup_tables| {
        try CompactU16.serialize(writer, @truncate(address_lookup_tables.len)); // WARN: Truncate okay if transaction is valid
        for (address_lookup_tables) |address_lookup_table| {
            try address_lookup_table.serialize(writer);
        }
    }
}

/// TODO: Check for validity of the transaction as it is deserialized and
/// return an error if the transaction is invalid.
/// [firedancer] https://github.com/firedancer-io/firedancer/blob/8f77acd876ba3c13b6628b66c4266c0454a357f7/src/ballet/txn/fd_txn_parse.c#L7
pub fn deserialize(allocator: std.mem.Allocator, reader: anytype) !Transaction {
    // Read number of signatures
    const signatures_len = try reader.readByte();

    // Read signatures
    const signatures = try allocator.alloc(Signature, signatures_len);
    errdefer allocator.free(signatures);
    for (0..signatures_len) |j| {
        signatures[j] = .{ .data = (try reader.readBytes(Signature.size))[0..Signature.size].* };
    }

    // Check the first byte of the header to determine the version and read
    // signature count accordingly.
    const version = if (((try reader.peekByte()) & VERSION_PREFIX) != 0)
        if (((try reader.readByte()) & ~VERSION_PREFIX) != 0)
            Version.V0
        else
            @panic("invalid version")
    else
        Version.Legacy;

    // Check the number of signatures
    const signature_count = try reader.readByte();

    // Read number of readonly signed accounts
    const readonly_signed_count = try reader.readByte();

    // Read number of readonly unsigned accounts
    const readonly_unsigned_count = try reader.readByte();

    // Read number of accounts
    const accounts_len = try CompactU16.deserialize(reader);

    // Read accounts
    const account_ids = try allocator.alloc(Pubkey, accounts_len);
    errdefer allocator.free(account_ids);
    for (0..accounts_len) |j| {
        account_ids[j] = .{ .data = (try reader.readBytes(Pubkey.size))[0..Pubkey.size].* };
    }

    // Read recent blockhash
    const recent_blockhash = .{ .data = (try reader.readBytes(Hash.size))[0..Hash.size].* };

    // Read instructions
    const instructions_len = try CompactU16.deserialize(reader);

    // Read instructions
    const instructions = try allocator.alloc(Instruction, instructions_len);
    errdefer allocator.free(instructions);
    for (0..instructions_len) |j| {
        instructions[j] = try Instruction.deserialize(reader);
    }

    // If the version is V0, read address lookup tables
    const maybe_address_lookup_tables: ?[]const AddressLookupTable = if (version == Version.V0) blk: {
        const address_lookup_tables_len = try CompactU16.deserialize(reader);

        const address_lookup_tables = try allocator.alloc(AddressLookupTable, address_lookup_tables_len);
        for (0..address_lookup_tables_len) |j| {
            address_lookup_tables[j] = try AddressLookupTable.deserialize(reader);
        }

        break :blk address_lookup_tables;
    } else null;

    // Return the parsed transaction
    return .{
        .signatures = signatures,
        .version = version,
        .signature_count = signature_count,
        .readonly_signed_count = readonly_signed_count,
        .readonly_unsigned_count = readonly_unsigned_count,
        .account_ids = account_ids,
        .recent_blockhash = recent_blockhash,
        .instructions = instructions,
        .maybe_address_lookup_tables = maybe_address_lookup_tables,
    };
}

test "test_legacy_transaction_parse" {
    const allocator = std.testing.allocator;

    const deserialized_transaction = try Transaction.readFromSlice(
        allocator,
        example_legacy_transaction.as_bytes[0..],
    );
    defer deserialized_transaction.deinit(allocator);

    var serialize_buffer = [_]u8{0} ** MAX_BYTES;
    const serialized_transaction = try deserialized_transaction.writeToSlice(&serialize_buffer);

    try std.testing.expectEqualSlices(
        u8,
        example_legacy_transaction.as_bytes[0..],
        serialized_transaction,
    );
}

pub const example_legacy_transaction = struct {
    const as_struct = Transaction{
        .signatures = &.{
            Signature.fromString("Z2hT7E85gqWWVKEsZXxJ184u7rXdRnB6EKz2PHAUajx6jHrUZhN5WkE7tPw6PrUA3XzeZRjoE7xJDtQzshZm1Pk") catch unreachable,
        },
        .version = Version.Legacy,
        .signature_count = 1,
        .readonly_signed_count = 0,
        .readonly_unsigned_count = 1,
        .account_ids = &.{
            Pubkey.fromString("4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS") catch unreachable,
            Pubkey.fromString("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi") catch unreachable,
            Pubkey.fromString("11111111111111111111111111111111") catch unreachable,
        },
        .recent_blockhash = Hash.parseBase58String("8RBsoeyoRwajj86MZfZE6gMDJQVYGYcdSfx1zxqxNHbr") catch unreachable,
        .instructions = &.{.{
            .program_id_index = 2,
            .accounts = &.{ 0, 1 },
            .data = &.{ 2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0 },
        }},
        .maybe_address_lookup_tables = null,
    };

    const as_bytes = [_]u8{
        1,   27,  158, 238, 65,  248, 46,  208, 15,  65,  178, 83,  163, 117, 224, 86,  163,
        91,  67,  228, 176, 117, 246, 111, 69,  133, 194, 78,  89,  205, 86,  166, 98,  22,
        27,  163, 250, 167, 208, 146, 201, 53,  24,  212, 97,  230, 100, 176, 26,  194, 121,
        177, 18,  155, 167, 75,  230, 252, 22,  204, 75,  19,  13,  3,   7,   1,   0,   1,
        3,   59,  106, 39,  188, 206, 182, 164, 45,  98,  163, 168, 208, 42,  111, 13,  115,
        101, 50,  21,  119, 29,  226, 67,  166, 58,  192, 72,  161, 139, 89,  218, 41,  1,
        1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
        1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   110, 52,  11,  156, 255,
        179, 122, 152, 156, 165, 68,  230, 187, 120, 10,  44,  120, 144, 29,  63,  179, 55,
        56,  118, 133, 17,  163, 6,   23,  175, 160, 29,  1,   2,   2,   0,   1,   12,  2,
        0,   0,   0,   100, 0,   0,   0,   0,   0,   0,   0,
    };
};

pub const example_v0_transaction = struct {
    pub const as_struct = Transaction{
        .signatures = &.{
            Signature.fromString("Z2hT7E85gqWWVKEsZXxJ184u7rXdRnB6EKz2PHAUajx6jHrUZhN5WkE7tPw6PrUA3XzeZRjoE7xJDtQzshZm1Pk") catch unreachable,
        },
        .version = Version.V0,
        .signature_count = 39,
        .readonly_signed_count = 12,
        .readonly_unsigned_count = 102,
        .account_ids = &.{
            Pubkey.fromString("GubTBrbgk9JwkwX1FkXvsrF1UC2AP7iTgg8SGtgH14QE") catch unreachable,
            Pubkey.fromString("5yCD7QeAk5uAduhLZGxePv21RLsVEktPqJG5pbmZx4J4") catch unreachable,
        },
        .recent_blockhash = Hash.parseBase58String("4xzjBNLkRqhBVmZ7JKcX2UEP8wzYKYWpXk7CPXzgrEZW") catch unreachable,
        .instructions = &.{.{
            .program_id_index = 100,
            .accounts = &.{ 1, 3 },
            .data = &.{
                104, 232, 42,  254, 46, 48, 104, 89,  101, 211, 253, 161, 65, 155, 204, 89,
                126, 187, 180, 191, 60, 59, 88,  119, 106, 20,  194, 80,  11, 200, 76,  0,
            },
        }},
        .maybe_address_lookup_tables = &.{.{
            .account_address = Pubkey.fromString("ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD") catch unreachable,
            .writable_indexes = &.{ 1, 3, 5, 7, 90 },
            .readonly_indexes = &.{},
        }},
    };

    pub const as_bytes = [_]u8{
        128, 39,  12,  102, 2,   236, 88,  117, 221, 34,  125, 55,  183, 193, 174, 21,  99,  70,
        167, 52,  227, 254, 241, 14,  239, 13,  172, 158, 81,  254, 134, 30,  78,  35,  15,  168,
        79,  73,  211, 242, 100, 122, 21,  163, 216, 62,  58,  230, 205, 163, 112, 95,  100, 134,
        113, 98,  129, 164, 240, 184, 157, 4,   34,  55,  72,  89,  113, 179, 97,  58,  235, 71,
        20,  83,  42,  196, 46,  189, 136, 194, 90,  249, 14,  154, 144, 141, 234, 253, 148, 146,
        168, 110, 10,  237, 82,  157, 190, 248, 20,  215, 105, 1,   100, 2,   1,   3,   32,  104,
        232, 42,  254, 46,  48,  104, 89,  101, 211, 253, 161, 65,  155, 204, 89,  126, 187, 180,
        191, 60,  59,  88,  119, 106, 20,  194, 80,  11,  200, 76,  0,   1,   8,   65,  203, 149,
        184, 2,   85,  213, 101, 44,  13,  181, 13,  65,  128, 17,  94,  229, 31,  215, 47,  49,
        72,  57,  158, 144, 193, 224, 205, 241, 120, 78,  5,   1,   3,   5,   7,   90,  0,
    };
};
