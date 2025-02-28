const std = @import("std");
const sig = @import("../sig.zig");

const leb = std.leb;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

const shortVecConfig = sig.bincode.shortvec.sliceConfig;

pub const Transaction = struct {
    /// Signatures
    signatures: []Signature,

    /// The version, either legacy or v0.
    version: TransactionVersion,

    /// The signable data of a transaction
    msg: TransactionMessage,

    /// MAX_BYTES is the maximum size of a transaction.
    pub const MAX_BYTES: u32 = 1232;

    /// MAX_SIGNATURES is the maximum number of signatures that can be applied to a transaction.
    pub const MAX_SIGNATURES: u8 = 127;

    /// MAX_ACCOUNTS is the maximum number of accounts that can be loaded by a transaction.
    pub const MAX_ACCOUNTS: u16 = 128;

    /// MAX_INSTRUCTIONS is the maximum number of instructions that can be executed by a transaction.
    pub const MAX_INSTRUCTIONS: u8 = 64;

    /// MAX_ADDRESS_LOOKUP_TABLES is the maximum number of address lookup tables that can be used by a transaction.
    pub const MAX_ADDRESS_LOOKUP_TABLES: u16 = 127;

    /// VERSION_PREFIX is used to differentiate between legacy and versioned transactions. If the first byte after the
    /// signatures has its high bit set, then the transaction is versioned and the remaining bits represent the version.
    /// Otherwise, the transaction is legacy and the first byte after the signatures is the first byte of the message.
    pub const VERSION_PREFIX: u8 = 0x80;

    pub const @"!bincode-config": sig.bincode.FieldConfig(Transaction) = .{
        .deserializer = deserialize,
        .serializer = serialize,
    };

    pub const EMPTY = Transaction{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 0,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{},
            .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };

    pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
        sig.bincode.free(allocator, self);
    }

    pub fn clone(self: Transaction, allocator: std.mem.Allocator) !Transaction {
        const signatures = try allocator.dupe(Signature, self.signatures);
        errdefer allocator.free(signatures);
        return .{
            .signatures = signatures,
            .version = self.version,
            .msg = try self.msg.clone(allocator),
        };
    }

    pub fn serialize(writer: anytype, data: anytype, _: sig.bincode.Params) !void {
        try leb.writeULEB128(writer, @as(u16, @truncate(data.signatures.len)));
        for (data.signatures) |sgn| try writer.writeAll(&sgn.data);
        try data.version.serialize(writer);
        try data.msg.serialize(writer, data.version);
    }

    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, _: sig.bincode.Params) !Transaction {
        const signatures = try allocator.alloc(Signature, try leb.readULEB128(u16, reader));
        for (signatures) |*sgn| sgn.* = .{ .data = try reader.readBytesNoEof(Signature.SIZE) };
        var peekable = sig.utils.io.peekableReader(reader);
        const version = try TransactionVersion.deserialize(&peekable);
        return .{
            .signatures = signatures,
            .version = version,
            .msg = try TransactionMessage.deserialize(allocator, peekable.reader(), version),
        };
    }

    pub fn validate(self: Transaction) !void {
        try self.msg.validate();
    }
};

pub const TransactionVersion = enum(u8) {
    /// Legacy transaction without address lookups.
    legacy = 0xFF,
    /// Transaction with address lookups.
    v0 = 0x00,

    pub fn serialize(self: TransactionVersion, writer: anytype) !void {
        if (self != .legacy)
            try writer.writeByte(Transaction.VERSION_PREFIX | @intFromEnum(self));
    }

    pub fn deserialize(peekable: anytype) !TransactionVersion {
        if (try peekable.peekByte() & Transaction.VERSION_PREFIX == 0)
            return TransactionVersion.legacy;

        const version = try peekable.reader().readByte();
        return switch (version & ~Transaction.VERSION_PREFIX) {
            0 => .v0,
            127 => error.OffChain,
            else => error.InvalidVersion,
        };
    }
};

pub const TransactionMessage = struct {
    /// The number of signatures required for this transaction to be considered
    /// valid. The signers of those signatures must match the first
    /// `signature_count` of `account_keys`.
    signature_count: u8,
    /// The last `readonly_signed_count` of the signed account keys are read-only accounts.
    readonly_signed_count: u8,
    /// The last `readonly_unsigned_count` of the unsigned account keys are read-only accounts.
    readonly_unsigned_count: u8,

    /// Addresses of accounts loaded by this transaction.
    account_keys: []const Pubkey,

    /// The blockhash of a recent block.
    recent_blockhash: Hash,

    /// Instructions that invoke a designated program, are executed in sequence,
    /// and committed in one atomic transaction if all succeed.
    ///
    /// # Notes
    ///
    /// Program indexes must index into the list of `account_keys` because
    /// program addresses cannot be dynamically loaded from a lookup table.
    ///
    /// Account indexes must index into the list of account keys
    /// constructed from the concatenation of three address lists:
    ///   1) `account_keys`
    ///   2) ordered list of account_keys loaded from `writable` lookup table indexes
    ///   3) ordered list of account_keys loaded from `readable` lookup table indexes
    instructions: []const TransactionInstruction,

    /// `AddressLookup`'s are used to load account addresses from lookup tables.
    address_lookups: []const TransactionAddressLookup = &.{},

    pub fn deinit(self: TransactionMessage, allocator: std.mem.Allocator) void {
        sig.bincode.free(allocator, self);
    }

    pub fn clone(self: TransactionMessage, allocator: std.mem.Allocator) !TransactionMessage {
        const account_keys = try allocator.dupe(Pubkey, self.account_keys);
        errdefer sig.bincode.free(allocator, account_keys);

        var instructions = try allocator.alloc(TransactionInstruction, self.instructions.len);
        errdefer sig.bincode.free(allocator, instructions);
        for (self.instructions, 0..) |instr, i|
            instructions[i] = try instr.clone(allocator);

        const address_lookups = try allocator.alloc(TransactionAddressLookup, self.address_lookups.len);
        errdefer sig.bincode.free(allocator, address_lookups);
        for (address_lookups, 0..) |*alt, i|
            alt.* = try self.address_lookups[i].clone(allocator);

        return .{
            .signature_count = self.signature_count,
            .readonly_signed_count = self.readonly_signed_count,
            .readonly_unsigned_count = self.readonly_unsigned_count,
            .account_keys = account_keys,
            .recent_blockhash = self.recent_blockhash,
            .instructions = instructions,
            .address_lookups = address_lookups,
        };
    }

    pub fn serialize(self: TransactionMessage, writer: anytype, version: TransactionVersion) !void {
        try writer.writeByte(self.signature_count);
        try writer.writeByte(self.readonly_signed_count);
        try writer.writeByte(self.readonly_unsigned_count);

        // WARN: Truncate okay if transaction is valid
        try leb.writeULEB128(writer, @as(u16, @truncate(self.account_keys.len)));
        for (self.account_keys) |id| try writer.writeAll(&id.data);

        try writer.writeAll(&self.recent_blockhash.data);

        // WARN: Truncate okay if transaction is valid
        try leb.writeULEB128(writer, @as(u16, @truncate(self.instructions.len)));
        for (self.instructions) |instr| try sig.bincode.write(writer, instr, .{});

        // WARN: Truncate okay if transaction is valid
        if (version != TransactionVersion.legacy) {
            try leb.writeULEB128(writer, @as(u16, @truncate(self.address_lookups.len)));
            for (self.address_lookups) |alt| try sig.bincode.write(writer, alt, .{});
        }
    }

    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, version: TransactionVersion) !TransactionMessage {
        const signature_count = try reader.readByte();
        const readonly_signed_count = try reader.readByte();
        const readonly_unsigned_count = try reader.readByte();

        const account_keys = try allocator.alloc(Pubkey, try leb.readULEB128(u16, reader));
        errdefer sig.bincode.free(allocator, account_keys);
        for (account_keys) |*id| id.* = .{ .data = try reader.readBytesNoEof(Pubkey.SIZE) };

        const recent_blockhash: Hash = .{ .data = try reader.readBytesNoEof(Hash.SIZE) };

        const instructions = try allocator.alloc(TransactionInstruction, try leb.readULEB128(u16, reader));
        errdefer sig.bincode.free(allocator, instructions);
        for (instructions) |*instr| instr.* = try sig.bincode.read(allocator, TransactionInstruction, reader, .{});

        const address_lookups_len = if (version == .legacy) 0 else try leb.readULEB128(u16, reader);
        const address_lookups = try allocator.alloc(TransactionAddressLookup, address_lookups_len);
        errdefer sig.bincode.free(allocator, address_lookups);
        for (address_lookups) |*alt| alt.* = try sig.bincode.read(allocator, TransactionAddressLookup, reader, .{});

        return .{
            .signature_count = signature_count,
            .readonly_signed_count = readonly_signed_count,
            .readonly_unsigned_count = readonly_unsigned_count,
            .account_keys = account_keys,
            .recent_blockhash = recent_blockhash,
            .instructions = instructions,
            .address_lookups = address_lookups,
        };
    }

    pub fn validate(self: TransactionMessage) !void {
        // number of accounts should match spec in header. signed and unsigned should not overlap.
        if (self.signature_count +| self.readonly_unsigned_count > self.account_keys.len)
            return error.NotEnoughAccounts;

        // there should be at least 1 RW fee-payer account.
        if (self.readonly_signed_count >= self.signature_count)
            return error.MissingWritableFeePayer;

        for (self.instructions) |ti| {
            if (ti.program_index >= self.account_keys.len)
                return error.ProgramIdAccountMissing;

            // A program cannot be a payer.
            if (ti.program_index == 0)
                return error.ProgramIdCannotBePayer;

            for (ti.account_indexes) |ai| {
                if (ai >= self.account_keys.len)
                    return error.AccountIndexOutOfBounds;
            }
        }
    }
};

pub const TransactionInstruction = struct {
    /// Index into the transactions account_keys array
    program_index: u8,
    /// Index into the concatenation of the transactions account_keys array,
    /// writable lookup results, and readable lookup results
    account_indexes: []const u8,
    /// Serialized program instruction.
    data: []const u8,

    pub const @"!bincode-config:account_indexes" = shortVecConfig([]const u8);
    pub const @"!bincode-config:data" = shortVecConfig([]const u8);

    pub fn deinit(self: TransactionInstruction, allocator: std.mem.Allocator) void {
        sig.bincode.free(allocator, self);
    }

    pub fn clone(self: *const TransactionInstruction, allocator: std.mem.Allocator) !TransactionInstruction {
        const account_indexes = try allocator.dupe(u8, self.account_indexes);
        errdefer allocator.free(account_indexes);
        return .{
            .program_index = self.program_index,
            .account_indexes = account_indexes,
            .data = try allocator.dupe(u8, self.data),
        };
    }
};

pub const TransactionAddressLookup = struct {
    /// Address of the lookup table
    table_address: Pubkey,
    /// List of indexes used to load writable account ids
    writable_indexes: []const u8,
    /// List of indexes used to load readonly account ids
    readonly_indexes: []const u8,

    pub const @"!bincode-config:writable_indexes" = shortVecConfig([]const u8);
    pub const @"!bincode-config:readonly_indexes" = shortVecConfig([]const u8);

    pub fn deinit(self: TransactionAddressLookup, allocator: std.mem.Allocator) void {
        sig.bincode.free(allocator, self);
    }

    pub fn clone(self: *const TransactionAddressLookup, allocator: std.mem.Allocator) !TransactionAddressLookup {
        const writable_indexes = try allocator.dupe(u8, self.writable_indexes);
        errdefer allocator.free(writable_indexes);
        return .{
            .table_address = self.table_address,
            .writable_indexes = writable_indexes,
            .readonly_indexes = try allocator.dupe(u8, self.readonly_indexes),
        };
    }
};

test "clone transaction" {
    const allocator = std.testing.allocator;
    const transaction = Transaction{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{Pubkey.ZEROES},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };

    const clone = try transaction.clone(allocator);
    defer clone.deinit(allocator);

    try std.testing.expectEqual(transaction.signatures.len, clone.signatures.len);
    try std.testing.expectEqual(transaction.version, clone.version);
    try std.testing.expectEqual(transaction.msg.signature_count, clone.msg.signature_count);
    try std.testing.expectEqual(transaction.msg.readonly_signed_count, clone.msg.readonly_signed_count);
    try std.testing.expectEqual(transaction.msg.readonly_unsigned_count, clone.msg.readonly_unsigned_count);
    try std.testing.expectEqual(transaction.msg.account_keys.len, clone.msg.account_keys.len);
    try std.testing.expectEqual(transaction.msg.recent_blockhash, clone.msg.recent_blockhash);
    try std.testing.expectEqual(transaction.msg.instructions.len, clone.msg.instructions.len);
    try std.testing.expectEqual(transaction.msg.address_lookups.len, clone.msg.address_lookups.len);
}

test "sanitize succeeds minimal valid transaction" {
    const transaction = Transaction{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{Pubkey.ZEROES},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };
    try std.testing.expectEqual({}, transaction.validate());
}

test "sanitize fails empty transaction" {
    try std.testing.expectError(error.MissingWritableFeePayer, Transaction.EMPTY.validate());
}

test "sanitize fails missing signers" {
    const transaction = Transaction{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 2,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{Pubkey.ZEROES},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };
    try std.testing.expectEqual(error.NotEnoughAccounts, transaction.validate());
}

test "sanitize fails missing unsigned" {
    const transaction = Transaction{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 1,
            .account_keys = &.{Pubkey.ZEROES},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };
    try std.testing.expectEqual(error.NotEnoughAccounts, transaction.validate());
}

test "sanitize fails no writable signed" {
    const transaction = Transaction{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 1,
            .readonly_unsigned_count = 0,
            .account_keys = &.{ Pubkey.ZEROES, Pubkey.ZEROES },
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };
    try std.testing.expectEqual(error.MissingWritableFeePayer, transaction.validate());
}

test "sanitize fails missing program id" {
    const transaction = Transaction{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{Pubkey.ZEROES},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{.{
                .program_index = 1,
                .account_indexes = &.{},
                .data = &.{},
            }},
            .address_lookups = &.{},
        },
    };
    try std.testing.expectEqual(error.ProgramIdAccountMissing, transaction.validate());
}

test "sanitize fails if program id has index 0" {
    const transaction = Transaction{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{Pubkey.ZEROES},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{.{
                .program_index = 0,
                .account_indexes = &.{},
                .data = &.{},
            }},
            .address_lookups = &.{},
        },
    };
    try std.testing.expectEqual(error.ProgramIdCannotBePayer, transaction.validate());
}

test "satinize fails account index out of bounds" {
    const transaction = Transaction{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 1,
            .account_keys = &.{ Pubkey.ZEROES, Pubkey.ZEROES },
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{.{
                .program_index = 1,
                .account_indexes = &.{2},
                .data = &.{},
            }},
            .address_lookups = &.{},
        },
    };
    try std.testing.expectEqual(error.AccountIndexOutOfBounds, transaction.validate());
}

test "parse legacy" {
    try sig.bincode.testRoundTrip(
        transaction_legacy_example.as_struct,
        &transaction_legacy_example.as_bytes,
    );
}

test "parse v0" {
    try sig.bincode.testRoundTrip(
        transaction_v0_example.as_struct,
        &transaction_v0_example.as_bytes,
    );
}

pub const transaction_legacy_example = struct {
    var signatures = [_]Signature{
        Signature.parseBase58String(
            "Z2hT7E85gqWWVKEsZXxJ184u7rXdRnB6EKz2PHAUajx6jHrUZhN5WkE7tPw6PrUA3XzeZRjoE7xJDtQzshZm1Pk",
        ) catch unreachable,
    };

    const as_struct = Transaction{
        .signatures = &signatures,
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 1,
            .account_keys = &.{
                Pubkey.parseBase58String("4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS") catch unreachable,
                Pubkey.parseBase58String("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi") catch unreachable,
                Pubkey.parseBase58String("11111111111111111111111111111111") catch unreachable,
            },
            .recent_blockhash = Hash.parseBase58String("8RBsoeyoRwajj86MZfZE6gMDJQVYGYcdSfx1zxqxNHbr") catch unreachable,
            .instructions = &.{.{
                .program_index = 2,
                .account_indexes = &.{ 0, 1 },
                .data = &.{ 2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0 },
            }},
            .address_lookups = &.{},
        },
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

pub const transaction_v0_example = struct {
    var signatures = [_]Signature{
        Signature.parseBase58String(
            "2cxn1LdtB7GcpeLEnHe5eA7LymTXKkqGF6UvmBM2EtttZEeqBREDaAD7LCagDFHyuc3xXxyDkMPiy3CpK5m6Uskw",
        ) catch unreachable,
        Signature.parseBase58String(
            "4gr9L7K3bALKjPRiRSk4JDB3jYmNaauf6rewNV3XFubX5EHxBn98gqBGhbwmZAB9DJ2pv8GWE1sLoYqhhLbTZcLj",
        ) catch unreachable,
    };

    pub const as_struct: Transaction = .{
        .signatures = signatures[0..],
        .version = .v0,
        .msg = .{
            .signature_count = 39,
            .readonly_signed_count = 12,
            .readonly_unsigned_count = 102,
            .account_keys = &.{
                Pubkey.parseBase58String("GubTBrbgk9JwkwX1FkXvsrF1UC2AP7iTgg8SGtgH14QE") catch unreachable,
                Pubkey.parseBase58String("5yCD7QeAk5uAduhLZGxePv21RLsVEktPqJG5pbmZx4J4") catch unreachable,
            },
            .recent_blockhash = Hash.parseBase58String("4xzjBNLkRqhBVmZ7JKcX2UEP8wzYKYWpXk7CPXzgrEZW") catch unreachable,
            .instructions = &.{.{
                .program_index = 100,
                .account_indexes = &.{ 1, 3 },
                .data = &.{
                    104, 232, 42,  254, 46, 48, 104, 89,  101, 211, 253, 161, 65, 155, 204, 89,
                    126, 187, 180, 191, 60, 59, 88,  119, 106, 20,  194, 80,  11, 200, 76,  0,
                },
            }},
            .address_lookups = &.{.{
                .table_address = Pubkey.parseBase58String("ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD") catch unreachable,
                .writable_indexes = &.{ 1, 3, 5, 7, 90 },
                .readonly_indexes = &.{},
            }},
        },
    };

    pub const as_bytes = [_]u8{
        2,   81,  7,   106, 50,  99,  54,  99,  92,  187, 47,  10,  170, 102, 132, 42,  25,  4,
        26,  67,  106, 76,  132, 119, 57,  38,  159, 7,   243, 132, 127, 236, 31,  83,  124, 56,
        140, 54,  239, 100, 65,  111, 8,   246, 103, 155, 246, 108, 196, 95,  231, 253, 121, 109,
        53,  222, 96,  249, 211, 168, 197, 148, 38,  209, 4,   184, 105, 238, 157, 236, 93,  219,
        197, 154, 48,  106, 71,  230, 220, 228, 253, 4,   34,  174, 202, 164, 57,  144, 240, 13,
        183, 169, 164, 90,  77,  21,  133, 150, 138, 9,   130, 196, 7,   48,  65,  73,  204, 64,
        157, 104, 93,  54,  46,  185, 1,   192, 88,  55,  179, 181, 207, 170, 11,  183, 143, 104,
        116, 71,  4,   128, 39,  12,  102, 2,   236, 88,  117, 221, 34,  125, 55,  183, 193, 174,
        21,  99,  70,  167, 52,  227, 254, 241, 14,  239, 13,  172, 158, 81,  254, 134, 30,  78,
        35,  15,  168, 79,  73,  211, 242, 100, 122, 21,  163, 216, 62,  58,  230, 205, 163, 112,
        95,  100, 134, 113, 98,  129, 164, 240, 184, 157, 4,   34,  55,  72,  89,  113, 179, 97,
        58,  235, 71,  20,  83,  42,  196, 46,  189, 136, 194, 90,  249, 14,  154, 144, 141, 234,
        253, 148, 146, 168, 110, 10,  237, 82,  157, 190, 248, 20,  215, 105, 1,   100, 2,   1,
        3,   32,  104, 232, 42,  254, 46,  48,  104, 89,  101, 211, 253, 161, 65,  155, 204, 89,
        126, 187, 180, 191, 60,  59,  88,  119, 106, 20,  194, 80,  11,  200, 76,  0,   1,   8,
        65,  203, 149, 184, 2,   85,  213, 101, 44,  13,  181, 13,  65,  128, 17,  94,  229, 31,
        215, 47,  49,  72,  57,  158, 144, 193, 224, 205, 241, 120, 78,  5,   1,   3,   5,   7,
        90,  0,
    };
};
