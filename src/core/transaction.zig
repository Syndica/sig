const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

const peekableReader = sig.utils.io.peekableReader;
const ShortVecConfig = sig.bincode.shortvec.ShortVecConfig;

pub const VersionedTransaction = struct {
    signatures: []Signature,
    message: VersionedMessage,

    pub const @"!bincode-config:signatures" = ShortVecConfig(Signature);

    pub fn deinit(self: VersionedTransaction, allocator: std.mem.Allocator) void {
        allocator.free(self.signatures);
        self.message.deinit(allocator);
    }

    pub fn sanitize(self: VersionedTransaction) !void {
        switch (self.message) {
            inline .legacy, .v0 => |m| try m.sanitize(),
        }
    }
};

const VersionedMessage = union(enum) {
    legacy: Message,
    v0: V0Message,

    pub fn deinit(self: VersionedMessage, allocator: std.mem.Allocator) void {
        switch (self) {
            inline .legacy, .v0 => |m| m.deinit(allocator),
        }
    }

    pub fn accountKeys(self: VersionedMessage) []const Pubkey {
        return switch (self) {
            inline .legacy, .v0 => |m| m.account_keys,
        };
    }

    pub const @"!bincode-config" = sig.bincode.FieldConfig(VersionedMessage){
        .serializer = bincode_config.serialize,
        .deserializer = bincode_config.deserialize,
        .free = bincode_config.free,
    };

    const bincode_config = struct {
        /// Bit mask that indicates whether a serialized message is versioned.
        const MESSAGE_VERSION_PREFIX: u8 = 0x80;

        fn serialize(writer: anytype, data: anytype, params: sig.bincode.Params) !void {
            const self: VersionedMessage = data;
            switch (self) {
                .legacy => |msg| {
                    try sig.bincode.write(writer, msg, params);
                },
                .v0 => |msg| {
                    try writer.writeByte(0x80);
                    try sig.bincode.write(writer, msg, params);
                },
            }
        }

        fn deserialize(
            allocator: std.mem.Allocator,
            original_reader: anytype,
            params: sig.bincode.Params,
        ) !VersionedMessage {
            var peekable = peekableReader(original_reader);
            const reader = peekable.reader();

            if (try peekable.peekByte() & MESSAGE_VERSION_PREFIX != 0) {
                return switch (try reader.readByte() & ~MESSAGE_VERSION_PREFIX) {
                    0 => .{ .v0 = try sig.bincode.read(allocator, V0Message, reader, params) },
                    127 => error.OffChainMessage,
                    else => error.InvalidMessageTag,
                };
            } else {
                return .{ .legacy = try sig.bincode.read(allocator, Message, reader, params) };
            }
        }

        fn free(allocator: std.mem.Allocator, data: anytype) void {
            VersionedMessage.deinit(data, allocator);
        }
    };
};

pub const V0Message = struct {
    /// The message header, identifying signed and read-only `account_keys`.
    /// Header values only describe static `account_keys`, they do not describe
    /// any additional account keys loaded via address table lookups.
    header: MessageHeader,

    /// List of accounts loaded by this transaction.
    account_keys: []Pubkey,

    /// The blockhash of a recent block.
    recent_blockhash: Hash,

    /// Instructions that invoke a designated program, are executed in sequence,
    /// and committed in one atomic transaction if all succeed.
    ///
    /// # Notes
    ///
    /// Program indexes must index into the list of message `account_keys` because
    /// program id's cannot be dynamically loaded from a lookup table.
    ///
    /// Account indexes must index into the list of addresses
    /// constructed from the concatenation of three key lists:
    ///   1) message `account_keys`
    ///   2) ordered list of keys loaded from `writable` lookup table indexes
    ///   3) ordered list of keys loaded from `readable` lookup table indexes
    instructions: []CompiledInstruction,

    /// List of address table lookups used to load additional accounts
    /// for this transaction.
    address_table_lookups: []MessageAddressTableLookup,

    pub const @"!bincode-config:account_keys" = ShortVecConfig(Pubkey);
    pub const @"!bincode-config:instructions" = ShortVecConfig(CompiledInstruction);
    pub const @"!bincode-config:address_table_lookups" = ShortVecConfig(MessageAddressTableLookup);

    pub fn deinit(self: V0Message, allocator: std.mem.Allocator) void {
        inline for (.{ self.instructions, self.address_table_lookups }) |slice| {
            for (slice) |item| {
                item.deinit(allocator);
            }
        }
        allocator.free(self.account_keys);
        allocator.free(self.instructions);
        allocator.free(self.address_table_lookups);
    }

    pub fn sanitize(_: V0Message) !void {
        // TODO
        std.debug.print("V0Message.sanitize not implemented", .{});
    }

    pub fn addressTableLookups(self: V0Message) ?[]MessageAddressTableLookup {
        switch (self) {
            .legacy => null,
            .v0 => |m| m.address_table_lookups,
        }
    }
};

pub const MessageAddressTableLookup = struct {
    /// Address lookup table account key
    account_key: Pubkey,
    /// List of indexes used to load writable account addresses
    writable_indexes: []u8,
    /// List of indexes used to load readonly account addresses
    readonly_indexes: []u8,

    pub const @"!bincode-config:writable_indexes" = ShortVecConfig(u8);
    pub const @"!bincode-config:readonly_indexes" = ShortVecConfig(u8);

    pub fn deinit(self: MessageAddressTableLookup, allocator: std.mem.Allocator) void {
        allocator.free(self.writable_indexes);
        allocator.free(self.readonly_indexes);
    }
};

pub const Transaction = struct {
    signatures: []Signature,
    message: Message,

    pub const @"!bincode-config:signatures" = ShortVecConfig(Signature);

    // used in tests
    pub fn default() Transaction {
        return Transaction{
            .signatures = &[_]Signature{},
            .message = Message.default(),
        };
    }

    pub fn clone(self: *const Transaction, allocator: std.mem.Allocator) error{OutOfMemory}!Transaction {
        return .{
            .signatures = try allocator.dupe(Signature, self.signatures),
            .message = try self.message.clone(allocator),
        };
    }

    pub fn deinit(self: *Transaction, allocator: std.mem.Allocator) void {
        allocator.free(self.signatures);
        self.message.deinit(allocator);
    }

    pub fn sanitize(self: *const Transaction) !void {
        const num_required_sigs = self.message.header.num_required_signatures;
        const num_signatures = self.signatures.len;
        if (num_required_sigs > num_signatures) {
            return error.InsufficientSignatures;
        }

        const num_account_keys = self.message.account_keys.len;
        if (num_signatures > num_account_keys) {
            return error.TooManySignatures;
        }
        try self.message.sanitize();
    }
};

pub const Message = struct {
    header: MessageHeader,
    account_keys: []Pubkey,
    recent_blockhash: Hash,
    instructions: []CompiledInstruction,

    pub const @"!bincode-config:account_keys" = ShortVecConfig(Pubkey);
    pub const @"!bincode-config:instructions" = ShortVecConfig(CompiledInstruction);

    pub fn default() Message {
        return Message{
            .header = MessageHeader{
                .num_required_signatures = 0,
                .num_readonly_signed_accounts = 0,
                .num_readonly_unsigned_accounts = 0,
            },
            .account_keys = &[_]Pubkey{},
            .recent_blockhash = Hash.generateSha256Hash(&[_]u8{0}),
            .instructions = &[_]CompiledInstruction{},
        };
    }

    pub fn clone(self: *const Message, allocator: std.mem.Allocator) error{OutOfMemory}!Message {
        const instructions = try allocator.alloc(CompiledInstruction, self.instructions.len);
        for (instructions, 0..) |*ci, i| ci.* = try self.instructions[i].clone(allocator);
        return .{
            .header = self.header,
            .account_keys = try allocator.dupe(Pubkey, self.account_keys),
            .recent_blockhash = self.recent_blockhash,
            .instructions = instructions,
        };
    }

    pub fn deinit(self: Message, allocator: std.mem.Allocator) void {
        allocator.free(self.account_keys);
        for (self.instructions) |*ci| ci.deinit(allocator);
        allocator.free(self.instructions);
    }

    pub const MessageSanitizeError = error{
        NotEnoughAccounts,
        MissingWritableFeePayer,
        ProgramIdAccountMissing,
        ProgramIdCannotBePayer,
        AccountIndexOutOfBounds,
    };

    pub fn sanitize(self: *const Message) MessageSanitizeError!void {
        // number of accounts should match spec in header. signed and unsigned should not overlap.
        if (self.header.num_required_signatures +| self.header.num_readonly_unsigned_accounts > self.account_keys.len) {
            return error.NotEnoughAccounts;
        }
        // there should be at least 1 RW fee-payer account.
        if (self.header.num_readonly_signed_accounts >= self.header.num_required_signatures) {
            return error.MissingWritableFeePayer;
        }

        for (self.instructions) |ci| {
            if (ci.program_id_index >= self.account_keys.len) {
                return error.ProgramIdAccountMissing;
            }
            // A program cannot be a payer.
            if (ci.program_id_index == 0) {
                return error.ProgramIdCannotBePayer;
            }
            for (ci.accounts) |ai| {
                if (ai >= self.account_keys.len) {
                    return error.AccountIndexOutOfBounds;
                }
            }
        }
    }
};

pub const MessageHeader = struct {
    /// The number of signatures required for this message to be considered
    /// valid. The signers of those signatures must match the first
    /// `num_required_signatures` of [`Message::account_keys`].
    // NOTE: Serialization-related changes must be paired with the direct read at sigverify.
    num_required_signatures: u8,

    /// The last `num_readonly_signed_accounts` of the signed keys are read-only
    /// accounts.
    num_readonly_signed_accounts: u8,

    /// The last `num_readonly_unsigned_accounts` of the unsigned keys are
    /// read-only accounts.
    num_readonly_unsigned_accounts: u8,
};

pub const CompiledInstruction = struct {
    /// Index into the transaction keys array indicating the program account that executes this instruction.
    program_id_index: u8,
    /// Ordered indices into the transaction keys array indicating which accounts to pass to the program.
    accounts: []u8,
    /// The program input data.
    data: []u8,

    pub const @"!bincode-config:accounts" = ShortVecConfig(u8);
    pub const @"!bincode-config:data" = ShortVecConfig(u8);

    pub fn clone(self: *const CompiledInstruction, allocator: std.mem.Allocator) error{OutOfMemory}!CompiledInstruction {
        return .{
            .program_id_index = self.program_id_index,
            .accounts = try allocator.dupe(u8, self.accounts),
            .data = try allocator.dupe(u8, self.data),
        };
    }

    pub fn deinit(self: CompiledInstruction, allocator: std.mem.Allocator) void {
        allocator.free(self.accounts);
        allocator.free(self.data);
    }
};

test "core.transaction: tmp" {
    const msg = Message.default();
    try std.testing.expect(msg.account_keys.len == 0);
}

test "core.transaction: blank Message fails to sanitize" {
    try std.testing.expect(error.MissingWritableFeePayer == Message.default().sanitize());
}

test "core.transaction: minimal valid Message sanitizes" {
    var pubkeys = [_]Pubkey{Pubkey.default()};
    const message = Message{
        .header = MessageHeader{
            .num_required_signatures = 1,
            .num_readonly_signed_accounts = 0,
            .num_readonly_unsigned_accounts = 0,
        },
        .account_keys = &pubkeys,
        .recent_blockhash = Hash.generateSha256Hash(&[_]u8{0}),
        .instructions = &[_]CompiledInstruction{},
    };
    try message.sanitize();
}

test "core.transaction: Message sanitize fails if missing signers" {
    var pubkeys = [_]Pubkey{Pubkey.default()};
    const message = Message{
        .header = MessageHeader{
            .num_required_signatures = 2,
            .num_readonly_signed_accounts = 0,
            .num_readonly_unsigned_accounts = 0,
        },
        .account_keys = &pubkeys,
        .recent_blockhash = Hash.generateSha256Hash(&[_]u8{0}),
        .instructions = &[_]CompiledInstruction{},
    };
    try std.testing.expect(error.NotEnoughAccounts == message.sanitize());
}

test "core.transaction: Message sanitize fails if missing unsigned" {
    var pubkeys = [_]Pubkey{Pubkey.default()};
    const message = Message{
        .header = MessageHeader{
            .num_required_signatures = 1,
            .num_readonly_signed_accounts = 0,
            .num_readonly_unsigned_accounts = 1,
        },
        .account_keys = &pubkeys,
        .recent_blockhash = Hash.generateSha256Hash(&[_]u8{0}),
        .instructions = &[_]CompiledInstruction{},
    };
    try std.testing.expect(error.NotEnoughAccounts == message.sanitize());
}

test "core.transaction: Message sanitize fails if no writable signed" {
    var pubkeys = [_]Pubkey{ Pubkey.default(), Pubkey.default() };
    const message = Message{
        .header = MessageHeader{
            .num_required_signatures = 1,
            .num_readonly_signed_accounts = 1,
            .num_readonly_unsigned_accounts = 0,
        },
        .account_keys = &pubkeys,
        .recent_blockhash = Hash.generateSha256Hash(&[_]u8{0}),
        .instructions = &[_]CompiledInstruction{},
    };
    try std.testing.expect(error.MissingWritableFeePayer == message.sanitize());
}

test "core.transaction: Message sanitize fails if missing program id" {
    var pubkeys = [_]Pubkey{Pubkey.default()};
    var instructions = [_]CompiledInstruction{.{
        .program_id_index = 1,
        .accounts = &[_]u8{},
        .data = &[_]u8{},
    }};
    const message = Message{
        .header = MessageHeader{
            .num_required_signatures = 1,
            .num_readonly_signed_accounts = 0,
            .num_readonly_unsigned_accounts = 0,
        },
        .account_keys = &pubkeys,
        .recent_blockhash = Hash.generateSha256Hash(&[_]u8{0}),
        .instructions = &instructions,
    };
    try std.testing.expect(error.ProgramIdAccountMissing == message.sanitize());
}

test "core.transaction: Message sanitize fails if program id has index 0" {
    var pubkeys = [_]Pubkey{Pubkey.default()};
    var instructions = [_]CompiledInstruction{.{
        .program_id_index = 0,
        .accounts = &[_]u8{},
        .data = &[_]u8{},
    }};
    const message = Message{
        .header = MessageHeader{
            .num_required_signatures = 1,
            .num_readonly_signed_accounts = 0,
            .num_readonly_unsigned_accounts = 0,
        },
        .account_keys = &pubkeys,
        .recent_blockhash = Hash.generateSha256Hash(&[_]u8{0}),
        .instructions = &instructions,
    };
    try std.testing.expect(error.ProgramIdCannotBePayer == message.sanitize());
}

test "core.transaction: Message sanitize fails if account index is out of bounds" {
    var pubkeys = [_]Pubkey{ Pubkey.default(), Pubkey.default() };
    var accounts = [_]u8{2};
    var instructions = [_]CompiledInstruction{.{
        .program_id_index = 1,
        .accounts = &accounts,
        .data = &[_]u8{},
    }};
    const message = Message{
        .header = MessageHeader{
            .num_required_signatures = 1,
            .num_readonly_signed_accounts = 0,
            .num_readonly_unsigned_accounts = 1,
        },
        .account_keys = &pubkeys,
        .recent_blockhash = Hash.generateSha256Hash(&[_]u8{0}),
        .instructions = &instructions,
    };
    try std.testing.expect(error.AccountIndexOutOfBounds == message.sanitize());
}

test "V0Message serialization and deserialization" {
    try sig.bincode.testRoundTrip(V0Message, test_v0_message);
}

test "VersionedTransaction v0 serialization and deserialization" {
    try sig.bincode.testRoundTrip(VersionedTransaction, test_v0_transaction);
}

test "VersionedMessage v0 serialization and deserialization" {
    try sig.bincode.testRoundTrip(VersionedMessage, test_v0_versioned_message);
}

pub const test_v0_transaction = struct {
    pub fn asStruct(allocator: std.mem.Allocator) !VersionedTransaction {
        return VersionedTransaction{
            .signatures = try allocopy(allocator, Signature, &.{
                try Signature.fromString("2cxn1LdtB7GcpeLEnHe5eA7LymTXKkqGF6UvmBM2EtttZEeqBREDaAD7LCagDFHyuc3xXxyDkMPiy3CpK5m6Uskw"),
                try Signature.fromString("4gr9L7K3bALKjPRiRSk4JDB3jYmNaauf6rewNV3XFubX5EHxBn98gqBGhbwmZAB9DJ2pv8GWE1sLoYqhhLbTZcLj"),
            }),
            .message = .{ .v0 = try test_v0_message.asStruct(allocator) },
        };
    }

    pub const bincode_serialized_bytes = [_]u8{
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

pub const test_v0_versioned_message = struct {
    pub fn asStruct(allocator: std.mem.Allocator) !VersionedMessage {
        return .{ .v0 = try test_v0_message.asStruct(allocator) };
    }

    pub const bincode_serialized_bytes = [_]u8{
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

pub const test_v0_message = struct {
    pub fn asStruct(allocator: std.mem.Allocator) !V0Message {
        return V0Message{
            .header = MessageHeader{
                .num_required_signatures = 39,
                .num_readonly_signed_accounts = 12,
                .num_readonly_unsigned_accounts = 102,
            },
            .account_keys = try allocopy(allocator, Pubkey, &.{
                try Pubkey.fromString("GubTBrbgk9JwkwX1FkXvsrF1UC2AP7iTgg8SGtgH14QE"),
                try Pubkey.fromString("5yCD7QeAk5uAduhLZGxePv21RLsVEktPqJG5pbmZx4J4"),
            }),
            .recent_blockhash = try Hash
                .parseBase58String("4xzjBNLkRqhBVmZ7JKcX2UEP8wzYKYWpXk7CPXzgrEZW"),
            .instructions = try allocopy(allocator, CompiledInstruction, &.{.{
                .program_id_index = 100,
                .accounts = try allocopy(allocator, u8, &.{ 1, 3 }),
                .data = try allocopy(allocator, u8, &.{
                    104, 232, 42,  254, 46, 48, 104, 89,  101, 211, 253, 161, 65, 155, 204, 89,
                    126, 187, 180, 191, 60, 59, 88,  119, 106, 20,  194, 80,  11, 200, 76,  0,
                }),
            }}),
            .address_table_lookups = try allocopy(allocator, MessageAddressTableLookup, &.{.{
                .account_key = try Pubkey.fromString("ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD"),
                .writable_indexes = try allocopy(allocator, u8, &.{ 1, 3, 5, 7, 90 }),
                .readonly_indexes = try allocopy(allocator, u8, &.{}),
            }}),
        };
    }

    pub const bincode_serialized_bytes = [_]u8{
        39,  12,  102, 2,   236, 88,  117, 221, 34,  125, 55,  183, 193, 174, 21,  99,  70,  167,
        52,  227, 254, 241, 14,  239, 13,  172, 158, 81,  254, 134, 30,  78,  35,  15,  168, 79,
        73,  211, 242, 100, 122, 21,  163, 216, 62,  58,  230, 205, 163, 112, 95,  100, 134, 113,
        98,  129, 164, 240, 184, 157, 4,   34,  55,  72,  89,  113, 179, 97,  58,  235, 71,  20,
        83,  42,  196, 46,  189, 136, 194, 90,  249, 14,  154, 144, 141, 234, 253, 148, 146, 168,
        110, 10,  237, 82,  157, 190, 248, 20,  215, 105, 1,   100, 2,   1,   3,   32,  104, 232,
        42,  254, 46,  48,  104, 89,  101, 211, 253, 161, 65,  155, 204, 89,  126, 187, 180, 191,
        60,  59,  88,  119, 106, 20,  194, 80,  11,  200, 76,  0,   1,   8,   65,  203, 149, 184,
        2,   85,  213, 101, 44,  13,  181, 13,  65,  128, 17,  94,  229, 31,  215, 47,  49,  72,
        57,  158, 144, 193, 224, 205, 241, 120, 78,  5,   1,   3,   5,   7,   90,  0,
    };
};

fn allocopy(allocator: std.mem.Allocator, comptime T: type, source: []const T) ![]T {
    const new_slice = try allocator.alloc(T, source.len);
    @memcpy(new_slice, source);
    return new_slice;
}
