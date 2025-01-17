const std = @import("std");
const sig = @import("../sig.zig");

const leb = std.leb;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const CheckedReader = sig.utils.io.CheckedReader;

pub const Transaction = struct {
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

    /// Signatures
    signatures: []const Signature,

    /// The message version, either legacy or v0.
    version: Version,

    /// The number of signatures required for this transaction to be considered
    /// valid. The signers of those signatures must match the first
    /// `signature_count` of `addresses`.
    signature_count: u8,
    /// The last `readonly_signed_count` of the signed addresses are read-only accounts.
    readonly_signed_count: u8,
    /// The last `readonly_unsigned_count` of the unsigned addresses are read-only accounts.
    readonly_unsigned_count: u8,

    /// Addresses of accounts loaded by this transaction.
    addresses: []const Pubkey,

    /// The blockhash of a recent block.
    recent_blockhash: Hash,

    /// Instructions that invoke a designated program, are executed in sequence,
    /// and committed in one atomic transaction if all succeed.
    ///
    /// # Notes
    ///
    /// Program indexes must index into the list of `addresses` because
    /// program addresses cannot be dynamically loaded from a lookup table.
    ///
    /// Account indexes must index into the list of addresses
    /// constructed from the concatenation of three address lists:
    ///   1) `addresses`
    ///   2) ordered list of addresses loaded from `writable` lookup table indexes
    ///   3) ordered list of addresses loaded from `readable` lookup table indexes
    instructions: []const Instruction,

    /// `AddressLookup`'s are used to load account addresses from lookup tables.
    maybe_address_lookups: ?[]const AddressLookup,

    pub const Version = enum(u8) {
        /// Legacy transaction without address lookups.
        Legacy = 0xFF,
        /// Transaction with address lookups.
        V0 = 0x00,

        pub fn serialize(self: Version, writer: anytype) !void {
            switch (self) {
                Version.Legacy => {},
                Version.V0 => try writer.writeByte(0x80),
            }
        }

        pub fn deserialize(reader: *CheckedReader) !Version {
            if (try reader.peekByte() & 0x80 == 0x80)
                return if (try reader.readByte() == 0x80) Version.V0 else error.InvalidVersion;
            return Version.Legacy;
        }
    };

    pub const Instruction = struct {
        /// Index into the transaction accounts array indicating the program account that executes this instruction.
        program_index: u8,
        /// TODO: Is this accurate, more likely an index into the concatenation of the three address lists.
        /// Ordered indices into the transaction accounts array indicating which accounts to pass to the program.
        account_indexes: []const u8,
        /// Serialized program instruction.
        program_instruction: []const u8,

        pub fn clone(self: *const Instruction, allocator: std.mem.Allocator) !Instruction {
            return .{
                .program_index = self.program_index,
                .account_indexes = try allocator.dupe(u8, self.account_indexes),
                .program_instruction = try allocator.dupe(u8, self.program_instruction),
            };
        }

        pub fn deinit(self: Instruction, allocator: std.mem.Allocator) void {
            allocator.free(self.account_indexes);
            allocator.free(self.program_instruction);
        }

        pub fn serialize(self: *const Instruction, writer: anytype) !void {
            try writer.writeByte(self.program_index);

            // WARN: Truncate okay if transaction is valid
            try leb.writeULEB128(writer, @as(u16, @truncate(self.account_indexes.len)));
            try writer.writeAll(self.account_indexes);

            // WARN: Truncate okay if transaction is valid
            try leb.writeULEB128(writer, @as(u16, @truncate(self.program_instruction.len)));
            try writer.writeAll(self.program_instruction);
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: *CheckedReader) !Instruction {
            const program_index = try reader.readByte();

            const account_indexes =
                try reader.readBytesAlloc(allocator, try leb.readULEB128(u16, reader));
            errdefer allocator.free(account_indexes);

            const program_instruction =
                try reader.readBytesAlloc(allocator, try leb.readULEB128(u16, reader));
            errdefer allocator.free(program_instruction);

            return .{
                .program_index = program_index,
                .account_indexes = account_indexes,
                .program_instruction = program_instruction,
            };
        }
    };

    pub const AddressLookup = struct {
        /// Address of the lookup table
        table_address: Pubkey,
        /// List of indexes used to load writable account ids
        writable_indexes: []const u8,
        /// List of indexes used to load readonly account ids
        readonly_indexes: []const u8,

        pub fn clone(self: *const AddressLookup, allocator: std.mem.Allocator) !AddressLookup {
            const writable_indexes = try allocator.dupe(u8, self.writable_indexes);
            errdefer allocator.free(writable_indexes);
            const readonly_indexes = try allocator.dupe(u8, self.readonly_indexes);
            return .{
                .table_address = self.table_address,
                .writable_indexes = writable_indexes,
                .readonly_indexes = readonly_indexes,
            };
        }

        pub fn deinit(self: AddressLookup, allocator: std.mem.Allocator) void {
            allocator.free(self.writable_indexes);
            allocator.free(self.readonly_indexes);
        }

        pub fn serialize(self: *const AddressLookup, writer: anytype) !void {
            try writer.writeAll(&self.table_address.data);

            try leb.writeULEB128(writer, @as(u16, @truncate(self.writable_indexes.len)));
            try writer.writeAll(self.writable_indexes);

            try leb.writeULEB128(writer, @as(u16, @truncate(self.readonly_indexes.len)));
            try writer.writeAll(self.readonly_indexes);
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: *CheckedReader) !AddressLookup {
            var table_address = Pubkey{ .data = [_]u8{0x00} ** Pubkey.size };
            try reader.readBytesInto(&table_address.data, Pubkey.size);

            const writable_indexes =
                try reader.readBytesAlloc(allocator, try leb.readULEB128(u16, reader));
            errdefer allocator.free(writable_indexes);

            const readonly_indexes =
                try reader.readBytesAlloc(allocator, try leb.readULEB128(u16, reader));
            errdefer allocator.free(readonly_indexes);

            return .{
                .table_address = table_address,
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

    pub fn empty() Transaction {
        return .{
            .signatures = &.{},
            .version = .Legacy,
            .signature_count = 0,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .addresses = &.{},
            .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.size },
            .instructions = &.{},
            .maybe_address_lookups = null,
        };
    }

    pub fn clone(self: Transaction, allocator: std.mem.Allocator) !Transaction {
        const signatures = try allocator.dupe(Signature, self.signatures);
        errdefer allocator.free(signatures);

        var instructions = try allocator.alloc(Instruction, self.instructions.len);
        errdefer {
            for (instructions) |instr| instr.deinit(allocator);
            allocator.free(instructions);
        }
        for (self.instructions, 0..) |instr, i|
            instructions[i] = try instr.clone(allocator);

        var maybe_address_lookups: ?[]AddressLookup = null;
        if (self.maybe_address_lookups) |alts| {
            maybe_address_lookups = try allocator.alloc(AddressLookup, alts.len);
            errdefer {
                for (maybe_address_lookups.?) |alt| alt.deinit(allocator);
                allocator.free(maybe_address_lookups.?);
            }
            for (alts, 0..) |alt, i|
                maybe_address_lookups.?[i] = try alt.clone(allocator);
        }

        const addresses = try allocator.dupe(Pubkey, self.addresses);

        return .{
            .signatures = signatures,
            .version = self.version,
            .signature_count = self.signature_count,
            .readonly_signed_count = self.readonly_signed_count,
            .readonly_unsigned_count = self.readonly_unsigned_count,
            .addresses = addresses,
            .recent_blockhash = self.recent_blockhash,
            .instructions = instructions,
            .maybe_address_lookups = maybe_address_lookups,
        };
    }

    pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
        allocator.free(self.signatures);
        allocator.free(self.addresses);
        for (self.instructions) |instr| instr.deinit(allocator);
        allocator.free(self.instructions);
        if (self.maybe_address_lookups) |alts| {
            for (alts) |alt| alt.deinit(allocator);
            allocator.free(alts);
        }
    }

    pub fn sanitize(self: Transaction) !void {
        // TODO: Implement
        _ = self;
    }

    /// Write a **valid** transaction to a slice of bytes.
    pub fn writeToSlice(self: Transaction, slice: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(slice);
        try self.serialize(&fbs.writer());
        return fbs.getWritten();
    }

    /// Read a transaction from a slice of bytes.
    /// Returns an error if the transaction is invalid.
    pub fn readFromSlice(allocator: std.mem.Allocator, slice: []const u8) !Transaction {
        var reader = CheckedReader.init(slice);
        return try Transaction.deserialize(allocator, &reader);
    }

    /// Serialize a **valid** transaction to a slice of bytes.
    pub fn serialize(self: Transaction, writer: anytype) !void {
        // WARN: Truncate okay if transaction is valid
        try writer.writeByte(@truncate(self.signatures.len));
        for (self.signatures) |sgn| try writer.writeAll(&sgn.data);
        try self.version.serialize(writer);
        try self.serializeSigned(writer);
    }

    /// Serialize the signed component of a **valid** transaction.
    pub fn serializeSigned(self: Transaction, writer: anytype) !void {
        try writer.writeByte(self.signature_count);
        try writer.writeByte(self.readonly_signed_count);
        try writer.writeByte(self.readonly_unsigned_count);

        // WARN: Truncate okay if transaction is valid
        try leb.writeULEB128(writer, @as(u16, @truncate(self.addresses.len)));
        for (self.addresses) |id| try writer.writeAll(&id.data);

        try writer.writeAll(&self.recent_blockhash.data);

        // WARN: Truncate okay if transaction is valid
        try leb.writeULEB128(writer, @as(u16, @truncate(self.instructions.len)));
        for (self.instructions) |instr| try instr.serialize(writer);

        // WARN: Truncate okay if transaction is valid
        if (self.maybe_address_lookups) |alts| {
            try leb.writeULEB128(writer, @as(u16, @truncate(alts.len)));
            for (alts) |alt| try alt.serialize(writer);
        }
    }

    /// TODO: Check for validity of the transaction as it is deserialized and return an error if the transaction is invalid.
    /// [firedancer] https://github.com/firedancer-io/firedancer/blob/8f77acd876ba3c13b6628b66c4266c0454a357f7/src/ballet/txn/fd_txn_parse.c#L7
    pub fn deserialize(allocator: std.mem.Allocator, reader: *CheckedReader) !Transaction {
        const signatures = try allocator.alloc(Signature, try reader.readByte());
        errdefer allocator.free(signatures);
        for (signatures) |*sgn| try reader.readBytesInto(sgn.data[0..], Signature.size);

        const version = try Version.deserialize(reader);
        const signature_count = try reader.readByte();
        const readonly_signed_count = try reader.readByte();
        const readonly_unsigned_count = try reader.readByte();

        const addresses = try allocator.alloc(Pubkey, try leb.readULEB128(u16, reader));
        errdefer allocator.free(addresses);
        for (addresses) |*id| try reader.readBytesInto(id.data[0..], Pubkey.size);

        const recent_blockhash = Hash{ .data = (try reader.readBytes(Hash.size))[0..Hash.size].* };

        const instructions = try allocator.alloc(Instruction, try leb.readULEB128(u16, reader));
        errdefer {
            for (instructions) |instr| instr.deinit(allocator);
            allocator.free(instructions);
        }
        for (instructions) |*instr| instr.* = try Instruction.deserialize(allocator, reader);

        const maybe_address_lookups = if (version == Version.V0) blk: {
            const alts = try allocator.alloc(AddressLookup, try leb.readULEB128(u16, reader));
            errdefer {
                for (alts) |alt| alt.deinit(allocator);
                allocator.free(alts);
            }
            for (alts) |*alt| alt.* = try AddressLookup.deserialize(allocator, reader);
            break :blk alts;
        } else null;

        return .{
            .signatures = signatures,
            .version = version,
            .signature_count = signature_count,
            .readonly_signed_count = readonly_signed_count,
            .readonly_unsigned_count = readonly_unsigned_count,
            .addresses = addresses,
            .recent_blockhash = recent_blockhash,
            .instructions = instructions,
            .maybe_address_lookups = maybe_address_lookups,
        };
    }
};

test "legacy_transaction_parse" {
    const allocator = std.testing.allocator;

    const deserialized_transaction = try Transaction.readFromSlice(
        allocator,
        transaction_legacy_example.as_bytes[0..],
    );
    defer deserialized_transaction.deinit(allocator);

    var serialize_buffer = [_]u8{0} ** Transaction.MAX_BYTES;
    const serialized_transaction = try deserialized_transaction.writeToSlice(&serialize_buffer);

    try std.testing.expectEqualSlices(
        u8,
        transaction_legacy_example.as_bytes[0..],
        serialized_transaction,
    );
}

pub const transaction_legacy_example = struct {
    const as_struct = Transaction{
        .signatures = &.{
            Signature.fromString("Z2hT7E85gqWWVKEsZXxJ184u7rXdRnB6EKz2PHAUajx6jHrUZhN5WkE7tPw6PrUA3XzeZRjoE7xJDtQzshZm1Pk") catch unreachable,
        },
        .version = .Legacy,
        .signature_count = 1,
        .readonly_signed_count = 0,
        .readonly_unsigned_count = 1,
        .addresses = &.{
            Pubkey.fromString("4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS") catch unreachable,
            Pubkey.fromString("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi") catch unreachable,
            Pubkey.fromString("11111111111111111111111111111111") catch unreachable,
        },
        .recent_blockhash = Hash.parseBase58String("8RBsoeyoRwajj86MZfZE6gMDJQVYGYcdSfx1zxqxNHbr") catch unreachable,
        .instructions = &.{.{
            .program_index = 2,
            .account_indexes = &.{ 0, 1 },
            .program_instruction = &.{ 2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0 },
        }},
        .maybe_address_lookups = null,
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
    pub const as_struct: Transaction = .{
        .signatures = &.{
            Signature.fromString(
                "2cxn1LdtB7GcpeLEnHe5eA7LymTXKkqGF6UvmBM2EtttZEeqBREDaAD7LCagDFHyuc3xXxyDkMPiy3CpK5m6Uskw",
            ) catch unreachable,
            Signature.fromString(
                "4gr9L7K3bALKjPRiRSk4JDB3jYmNaauf6rewNV3XFubX5EHxBn98gqBGhbwmZAB9DJ2pv8GWE1sLoYqhhLbTZcLj",
            ) catch unreachable,
        },
        .version = .V0,
        .signature_count = 39,
        .readonly_signed_count = 12,
        .readonly_unsigned_count = 102,
        .addresses = &.{
            Pubkey.fromString("GubTBrbgk9JwkwX1FkXvsrF1UC2AP7iTgg8SGtgH14QE") catch unreachable,
            Pubkey.fromString("5yCD7QeAk5uAduhLZGxePv21RLsVEktPqJG5pbmZx4J4") catch unreachable,
        },
        .recent_blockhash = Hash.parseBase58String("4xzjBNLkRqhBVmZ7JKcX2UEP8wzYKYWpXk7CPXzgrEZW") catch unreachable,
        .instructions = &.{.{
            .program_index = 100,
            .account_indexes = &.{ 1, 3 },
            .program_instruction = &.{
                104, 232, 42,  254, 46, 48, 104, 89,  101, 211, 253, 161, 65, 155, 204, 89,
                126, 187, 180, 191, 60, 59, 88,  119, 106, 20,  194, 80,  11, 200, 76,  0,
            },
        }},
        .maybe_address_lookups = &.{.{
            .table_address = Pubkey.fromString("ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD") catch unreachable,
            .writable_indexes = &.{ 1, 3, 5, 7, 90 },
            .readonly_indexes = &.{},
        }},
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
