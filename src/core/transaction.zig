const std = @import("std");
const sig = @import("../sig.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const KeyPair = Ed25519.KeyPair;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const indexOf = sig.utils.slice.indexOf;

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

    pub const MAX_BYTES: usize = 1232;

    pub fn default() Transaction {
        return Transaction{
            .signatures = &[_]Signature{},
            .message = Message.default(),
        };
    }

    pub fn newUnsigned(allocator: std.mem.Allocator, message: Message) error{OutOfMemory}!Transaction {
        return Transaction{
            .signatures = try allocator.alloc(Signature, message.header.num_required_signatures),
            .message = message,
        };
    }

    pub fn clone(self: *const Transaction, allocator: std.mem.Allocator) error{OutOfMemory}!Transaction {
        return .{
            .signatures = try allocator.dupe(Signature, self.signatures),
            .message = try self.message.clone(allocator),
        };
    }

    pub fn deinit(self: *const Transaction, allocator: std.mem.Allocator) void {
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

    pub fn init(allocator: std.mem.Allocator, instructions: []const Instruction, payer: Pubkey, recent_blockhash: Hash) !Message {
        var compiled_keys = try CompiledKeys.init(allocator, instructions, payer);
        defer compiled_keys.deinit();
        const header, const account_keys = try compiled_keys.intoMessageHeaderAndAccountKeys(allocator);
        const compiled_instructions = try compileInstructions(allocator, instructions, account_keys);
        return .{
            .header = header,
            .account_keys = account_keys,
            .recent_blockhash = recent_blockhash,
            .instructions = compiled_instructions,
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

    pub fn deinit(self: *const Message, allocator: std.mem.Allocator) void {
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

pub const Instruction = struct {
    program_id: Pubkey,
    accounts: []AccountMeta,
    data: []u8,

    pub fn initSystemInstruction(allocator: std.mem.Allocator, data: SystemInstruction, accounts: []AccountMeta) !Instruction {
        return .{
            .program_id = SYSTEM_PROGRAM_ID,
            .accounts = accounts,
            .data = try sig.bincode.writeAlloc(allocator, data, .{}),
        };
    }

    pub fn deinit(self: *const Instruction, allocator: std.mem.Allocator) void {
        allocator.free(self.accounts);
        allocator.free(self.data);
    }
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

    pub fn deinit(self: *const CompiledInstruction, allocator: std.mem.Allocator) void {
        allocator.free(self.accounts);
        allocator.free(self.data);
    }
};

pub const AccountMeta = struct {
    pubkey: Pubkey,
    is_signer: bool,
    is_writable: bool,

    pub fn newMutable(pubkey: Pubkey, is_signer: bool) AccountMeta {
        return .{
            .pubkey = pubkey,
            .is_signer = is_signer,
            .is_writable = true,
        };
    }

    pub fn newImmutable(pubkey: Pubkey, is_signer: bool) AccountMeta {
        return .{
            .pubkey = pubkey,
            .is_signer = is_signer,
            .is_writable = false,
        };
    }
};

pub const CompiledKeys = struct {
    maybe_payer: ?Pubkey,
    key_meta_map: std.AutoArrayHashMap(Pubkey, CompiledKeyMeta),

    pub fn init(allocator: std.mem.Allocator, instructions: []const Instruction, maybe_payer: ?Pubkey) !CompiledKeys {
        var key_meta_map = std.AutoArrayHashMap(Pubkey, CompiledKeyMeta).init(allocator);
        for (instructions) |instruction| {
            const instruction_meta_gopr = try key_meta_map.getOrPut(instruction.program_id);
            if (!instruction_meta_gopr.found_existing) {
                instruction_meta_gopr.value_ptr.* = CompiledKeyMeta.default();
            }
            instruction_meta_gopr.value_ptr.*.is_invoked = true;

            for (instruction.accounts) |account_meta| {
                const account_meta_gopr = try key_meta_map.getOrPut(account_meta.pubkey);
                if (!account_meta_gopr.found_existing) {
                    account_meta_gopr.value_ptr.* = CompiledKeyMeta.default();
                }
                account_meta_gopr.value_ptr.*.is_signer = account_meta_gopr.value_ptr.*.is_signer or account_meta.is_signer;
                account_meta_gopr.value_ptr.*.is_writable = account_meta_gopr.value_ptr.*.is_writable or account_meta.is_writable;
            }

            if (maybe_payer) |payer| {
                const payer_meta_gopr = try key_meta_map.getOrPut(payer);
                if (!payer_meta_gopr.found_existing) {
                    payer_meta_gopr.value_ptr.* = CompiledKeyMeta.default();
                }
                payer_meta_gopr.value_ptr.*.is_signer = true;
                payer_meta_gopr.value_ptr.*.is_writable = true;
            }
        }
        return .{ .maybe_payer = maybe_payer, .key_meta_map = key_meta_map };
    }

    pub fn deinit(self: *CompiledKeys) void {
        self.key_meta_map.deinit();
    }

    /// Creates message header and account keys from the compiled keys.
    /// Account keys memory is allocated and owned by the caller.
    pub fn intoMessageHeaderAndAccountKeys(self: *CompiledKeys, allocator: std.mem.Allocator) !struct { MessageHeader, []Pubkey } {
        const account_keys_buf = try allocator.alloc(Pubkey, self.key_meta_map.count() - @intFromBool(self.maybe_payer == null));
        errdefer allocator.free(account_keys_buf);

        var account_keys = std.ArrayListUnmanaged(Pubkey).initBuffer(account_keys_buf);

        var writable_signers_end: usize = 0;
        var readonly_signers_end: usize = 0;
        var writable_non_signers_end: usize = 0;

        if (self.maybe_payer) |payer| {
            _ = self.key_meta_map.swapRemove(payer);
            account_keys.insertAssumeCapacity(writable_signers_end, payer);
            writable_signers_end += 1;
            readonly_signers_end += 1;
            writable_non_signers_end += 1;
        }

        for (self.key_meta_map.keys(), self.key_meta_map.values()) |key, meta| {
            if (meta.is_signer and meta.is_writable) {
                account_keys.insertAssumeCapacity(writable_signers_end, key);
                writable_signers_end += 1;
                readonly_signers_end += 1;
                writable_non_signers_end += 1;
            } else if (meta.is_signer and !meta.is_writable) {
                account_keys.insertAssumeCapacity(readonly_signers_end, key);
                readonly_signers_end += 1;
                writable_non_signers_end += 1;
            } else if (!meta.is_signer and meta.is_writable) {
                account_keys.insertAssumeCapacity(writable_non_signers_end, key);
                writable_non_signers_end += 1;
            } else if (!meta.is_signer and !meta.is_writable) {
                account_keys.appendAssumeCapacity(key);
            } else unreachable;
        }

        std.debug.assert(account_keys.items.len == account_keys_buf.len);

        const header = MessageHeader{
            .num_required_signatures = @intCast(readonly_signers_end),
            .num_readonly_signed_accounts = @intCast(readonly_signers_end - writable_signers_end),
            .num_readonly_unsigned_accounts = @intCast(account_keys.items.len - writable_non_signers_end),
        };

        return .{ header, account_keys_buf };
    }
};

pub const CompiledKeyMeta = packed struct {
    is_signer: bool,
    is_writable: bool,
    is_invoked: bool,

    pub fn default() CompiledKeyMeta {
        return .{
            .is_signer = false,
            .is_writable = false,
            .is_invoked = false,
        };
    }
};

pub const CompileError = error{
    AccountIndexOverflow,
    AddressTableLookupIndexOverflow,
    UnknownInstructionKey,
};

const SYSTEM_PROGRAM_ID = Pubkey{ .data = [_]u8{0} ** Pubkey.size };

const SystemInstruction = union(enum(u8)) {
    CreateAccount,
    Assign,
    Transfer: struct {
        lamports: u64,
    },
};

pub fn buildTransferTansaction(allocator: std.mem.Allocator, from_keypair: KeyPair, from_pubkey: Pubkey, to_pubkey: Pubkey, lamports: u64, recent_blockhash: Hash) !Transaction {
    const transfer_instruction = try transfer(allocator, from_pubkey, to_pubkey, lamports);
    defer transfer_instruction.deinit(allocator);
    const instructions = [_]Instruction{transfer_instruction};

    const message = try Message.init(allocator, &instructions, from_pubkey, recent_blockhash);
    const message_bytes = try sig.bincode.writeAlloc(allocator, message, .{});
    defer allocator.free(message_bytes);

    var signatures = try allocator.alloc(Signature, 1);
    signatures[0] = Signature.init((try from_keypair.sign(message_bytes, null)).toBytes());

    return .{
        .signatures = signatures,
        .message = message,
    };
}

pub fn transfer(allocator: std.mem.Allocator, from_pubkey: Pubkey, to_pubkey: Pubkey, lamports: u64) !Instruction {
    var account_metas = try allocator.alloc(AccountMeta, 2);
    account_metas[0] = AccountMeta.newMutable(from_pubkey, true);
    account_metas[1] = AccountMeta.newMutable(to_pubkey, false);
    return try Instruction.initSystemInstruction(allocator, SystemInstruction{ .Transfer = .{ .lamports = lamports } }, account_metas);
}

pub fn compileInstruction(allocator: std.mem.Allocator, instruction: Instruction, account_keys: []const Pubkey) !CompiledInstruction {
    const program_id_index = indexOf(Pubkey, account_keys, instruction.program_id).?;
    var accounts = try allocator.alloc(u8, instruction.accounts.len);
    for (instruction.accounts, 0..) |account, i| {
        accounts[i] = @truncate(indexOf(Pubkey, account_keys, account.pubkey).?);
    }
    return .{
        .program_id_index = @truncate(program_id_index),
        .data = try allocator.dupe(u8, instruction.data),
        .accounts = accounts,
    };
}

pub fn compileInstructions(allocator: std.mem.Allocator, instructions: []const Instruction, account_keys: []const Pubkey) ![]CompiledInstruction {
    var compiled_instructions = try allocator.alloc(CompiledInstruction, instructions.len);
    for (instructions, 0..) |instruction, i| {
        compiled_instructions[i] = try compileInstruction(allocator, instruction, account_keys);
    }
    return compiled_instructions;
}

test "create transfer transaction" {
    const allocator = std.testing.allocator;
    const from_keypair = try KeyPair.create([_]u8{0} ** KeyPair.seed_length);
    const from_pubkey = Pubkey{ .data = from_keypair.public_key.bytes };
    const to_pubkey = Pubkey{ .data = [_]u8{1} ** Pubkey.size };
    const recent_blockhash = Hash.generateSha256Hash(&[_]u8{0});
    const tx = try buildTransferTansaction(allocator, from_keypair, from_pubkey, to_pubkey, 100, recent_blockhash);
    defer tx.deinit(allocator);
    const actual_bytes = try sig.bincode.writeAlloc(allocator, tx, .{});
    defer allocator.free(actual_bytes);
    const expected_bytes = [_]u8{
        1,   179, 96,  234, 171, 102, 151, 31,  74,  246, 57,  213, 75,  38,  199, 70,  105, 32,  146, 18,  245, 92,  92,  138,
        253, 30,  247, 119, 174, 140, 95,  67,  39,  148, 154, 255, 94,  118, 221, 113, 29,  20,  87,  102, 114, 28,  40,  39,
        125, 107, 122, 16,  63,  237, 139, 165, 163, 143, 40,  229, 32,  132, 188, 201, 2,   1,   0,   1,   3,   59,  106, 39,
        188, 206, 182, 164, 45,  98,  163, 168, 208, 42,  111, 13,  115, 101, 50,  21,  119, 29,  226, 67,  166, 58,  192, 72,
        161, 139, 89,  218, 41,  1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
        1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   110, 52,  11,
        156, 255, 179, 122, 152, 156, 165, 68,  230, 187, 120, 10,  44,  120, 144, 29,  63,  179, 55,  56,  118, 133, 17,  163,
        6,   23,  175, 160, 29,  1,   2,   2,   0,   1,   12,  2,   0,   0,   0,   100, 0,   0,   0,   0,   0,   0,   0,
    };
    try std.testing.expectEqualSlices(u8, &expected_bytes, actual_bytes);
}

test "tmp" {
    const msg = Message.default();
    try std.testing.expect(msg.account_keys.len == 0);
}

test "blank Message fails to sanitize" {
    try std.testing.expect(error.MissingWritableFeePayer == Message.default().sanitize());
}

test "minimal valid Message sanitizes" {
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

test "Message sanitize fails if missing signers" {
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

test "Message sanitize fails if missing unsigned" {
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

test "Message sanitize fails if no writable signed" {
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

test "Message sanitize fails if missing program id" {
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

test "Message sanitize fails if program id has index 0" {
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

test "Message sanitize fails if account index is out of bounds" {
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
    const message = try test_v0_message.asStruct(std.testing.allocator);
    defer message.deinit(std.testing.allocator);
    try sig.bincode.testRoundTrip(message, &test_v0_message.bincode_serialized_bytes);
}

test "VersionedTransaction v0 serialization and deserialization" {
    const transaction = try test_v0_transaction.asStruct(std.testing.allocator);
    defer transaction.deinit(std.testing.allocator);
    try sig.bincode.testRoundTrip(transaction, &test_v0_transaction.bincode_serialized_bytes);
}

test "VersionedMessage v0 serialization and deserialization" {
    const versioned_message = try test_v0_versioned_message.asStruct(std.testing.allocator);
    defer versioned_message.deinit(std.testing.allocator);
    try sig.bincode.testRoundTrip(versioned_message, &test_v0_versioned_message.bincode_serialized_bytes);
}

pub const test_v0_transaction = struct {
    pub fn asStruct(allocator: std.mem.Allocator) !VersionedTransaction {
        return VersionedTransaction{
            .signatures = try allocator.dupe(Signature, &.{
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
            .account_keys = try allocator.dupe(Pubkey, &.{
                try Pubkey.fromString("GubTBrbgk9JwkwX1FkXvsrF1UC2AP7iTgg8SGtgH14QE"),
                try Pubkey.fromString("5yCD7QeAk5uAduhLZGxePv21RLsVEktPqJG5pbmZx4J4"),
            }),
            .recent_blockhash = try Hash
                .parseBase58String("4xzjBNLkRqhBVmZ7JKcX2UEP8wzYKYWpXk7CPXzgrEZW"),
            .instructions = try allocator.dupe(CompiledInstruction, &.{.{
                .program_id_index = 100,
                .accounts = try allocator.dupe(u8, &.{ 1, 3 }),
                .data = try allocator.dupe(u8, &.{
                    104, 232, 42,  254, 46, 48, 104, 89,  101, 211, 253, 161, 65, 155, 204, 89,
                    126, 187, 180, 191, 60, 59, 88,  119, 106, 20,  194, 80,  11, 200, 76,  0,
                }),
            }}),
            .address_table_lookups = try allocator.dupe(MessageAddressTableLookup, &.{.{
                .account_key = try Pubkey.fromString("ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD"),
                .writable_indexes = try allocator.dupe(u8, &.{ 1, 3, 5, 7, 90 }),
                .readonly_indexes = try allocator.dupe(u8, &.{}),
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
