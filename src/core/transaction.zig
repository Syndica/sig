const std = @import("std");
const sig = @import("../sig.zig");

const leb = std.leb;

const Blake3 = std.crypto.hash.Blake3;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

const shortVecConfig = sig.bincode.shortvec.sliceConfig;

pub const Transaction = struct {
    /// Signatures
    signatures: []const Signature,

    /// The version, either legacy or v0.
    version: Version,

    /// The signable data of a transaction
    msg: Message,

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

    pub const EMPTY: Transaction = .{
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
        allocator.free(self.signatures);
        self.msg.deinit(allocator);
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

    pub const InitOwnedMsgWithSigningKeypairsError = error{
        /// Failed to serialize the provided message.
        BadMessage,
        /// Failed to sign the message with one of the keypairs.
        SigningError,
    } || std.mem.Allocator.Error;

    /// Takes ownership of the passed in `msg`, and signs it with all of the given keypairs.
    /// Assumes `msg` was allocated using the given `allocator`, since that will also be used
    /// to allocate space for the signatures.
    pub fn initOwnedMsgWithSigningKeypairs(
        allocator: std.mem.Allocator,
        version: Version,
        msg: Message,
        keypairs: []const sig.identity.KeyPair,
    ) InitOwnedMsgWithSigningKeypairsError!Transaction {
        const msg_bytes_bounded = msg.serializeBounded(version) catch return error.BadMessage;
        const msg_bytes = msg_bytes_bounded.constSlice();

        const signatures = try allocator.alloc(Signature, keypairs.len);
        errdefer allocator.free(signatures);

        for (signatures, keypairs) |*signature, keypair| {
            const msg_signature = keypair.sign(msg_bytes, null) catch return error.SigningError;
            signature.* = .{ .data = msg_signature.toBytes() };
        }

        return .{
            .signatures = signatures,
            .version = version,
            .msg = msg,
        };
    }

    pub fn serialize(writer: anytype, data: anytype, _: sig.bincode.Params) !void {
        std.debug.assert(data.signatures.len <= std.math.maxInt(u16));
        try leb.writeULEB128(writer, @as(u16, @intCast(data.signatures.len)));
        for (data.signatures) |sgn| try writer.writeAll(&sgn.data);
        try data.version.serialize(writer);
        try data.msg.serialize(writer, data.version);
    }

    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, _: sig.bincode.Params) !Transaction {
        const signatures = try allocator.alloc(Signature, try leb.readULEB128(u16, reader));
        errdefer allocator.free(signatures);
        for (signatures) |*sgn| sgn.* = .{ .data = try reader.readBytesNoEof(Signature.SIZE) };
        var peekable = sig.utils.io.peekableReader(reader);
        const version = try Version.deserialize(&peekable);
        return .{
            .signatures = signatures,
            .version = version,
            .msg = try Message.deserialize(allocator, peekable.reader(), version),
        };
    }

    /// Run some sanity checks on the message to ensure the internal data has consistency.
    ///
    /// Does *not* verify signatures. Call `verify` to verify signatures.
    pub fn validate(self: Transaction) !void {
        try self.msg.validate();
    }

    pub const VerifyError = error{
        /// The message is larger than the largest allowed transaction message size.
        NoSpaceLeft,
        /// Signature verification failure due to input being in wrong form.
        NonCanonical,
        /// There are not as many accounts as there are signatures.
        NotEnoughAccounts,
        /// A signature was invalid.
        SignatureVerificationFailed,
        /// The message could not be serialized.
        SerializationFailed,
    };

    /// Verify the transaction signatures.
    ///
    /// Does *not* ensure total internal consistency. Only does the minimum to
    /// verify signatures. Call `validate` to ensure full consistency.
    pub fn verify(self: Transaction) VerifyError!void {
        const serialized_message = self.msg.serializeBounded(self.version) catch
            return error.SerializationFailed;

        if (self.msg.account_keys.len < self.signatures.len) {
            return error.NotEnoughAccounts;
        }
        for (self.signatures, self.msg.account_keys[0..self.signatures.len]) |signature, pubkey| {
            if (!try signature.verify(pubkey, serialized_message.slice())) {
                return error.SignatureVerificationFailed;
            }
        }
    }

    /// Verify the transaction signatures and return the blake3 hash of the message.
    ///
    /// Does *not* ensure total internal consistency. Only does the minimum to
    /// verify signatures. Call `validate` to ensure full consistency.
    pub fn verifyAndHashMessage(self: Transaction) VerifyError!Hash {
        const serialized_message = self.msg.serializeBounded(self.version) catch
            return error.SerializationFailed;

        if (self.msg.account_keys.len < self.signatures.len) {
            return error.NotEnoughAccounts;
        }
        for (self.signatures, self.msg.account_keys[0..self.signatures.len]) |signature, pubkey| {
            if (!try signature.verify(pubkey, serialized_message.slice())) {
                return error.SignatureVerificationFailed;
            }
        }

        return Message.hash(serialized_message.slice());
    }

    /// Count the number of accounts in the slice of transactions,
    /// including accounts from lookup tables
    pub fn numAccounts(transactions: []const Transaction) usize {
        var total_accounts: usize = 0;
        for (transactions) |transaction| {
            total_accounts += transaction.msg.account_keys.len;
            for (transaction.msg.address_lookups) |lookup| {
                total_accounts += lookup.writable_indexes.len;
                total_accounts += lookup.readonly_indexes.len;
            }
        }
        return total_accounts;
    }
};

pub const Version = enum(u8) {
    /// Legacy transaction without address lookups.
    legacy = 0xFF,
    /// Transaction with address lookups.
    v0 = 0x00,

    pub fn serialize(self: Version, writer: anytype) !void {
        if (self != .legacy)
            try writer.writeByte(Transaction.VERSION_PREFIX | @intFromEnum(self));
    }

    pub fn deserialize(peekable: anytype) !Version {
        if (try peekable.peekByte() & Transaction.VERSION_PREFIX == 0)
            return Version.legacy;

        const version = try peekable.reader().readByte();
        return switch (version & ~Transaction.VERSION_PREFIX) {
            0 => .v0,
            127 => error.OffChain,
            else => error.InvalidVersion,
        };
    }
};

pub const Message = struct {
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
    instructions: []const Instruction,

    /// `AddressLookup`'s are used to load account addresses from lookup tables.
    address_lookups: []const AddressLookup = &.{},

    pub fn deinit(self: Message, allocator: std.mem.Allocator) void {
        allocator.free(self.account_keys);

        for (self.instructions) |inst| inst.deinit(allocator);
        allocator.free(self.instructions);

        for (self.address_lookups) |addr_lookup| addr_lookup.deinit(allocator);
        allocator.free(self.address_lookups);
    }

    pub fn clone(self: Message, allocator: std.mem.Allocator) !Message {
        const account_keys = try allocator.dupe(Pubkey, self.account_keys);
        errdefer sig.bincode.free(allocator, account_keys);

        var instructions = try allocator.alloc(Instruction, self.instructions.len);
        errdefer sig.bincode.free(allocator, instructions);
        for (self.instructions, 0..) |instr, i|
            instructions[i] = try instr.clone(allocator);

        const address_lookups =
            try allocator.alloc(AddressLookup, self.address_lookups.len);
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

    /// Compiles a transaction message.
    pub fn initCompile(
        allocator: std.mem.Allocator,
        instructions: []const sig.core.Instruction,
        payer: ?Pubkey,
        recent_blockhash: Hash,
        /// TODO: currently forced to be null by the compiler,
        /// will become a proper optional parameter in the future
        /// when v0 compilation is implemented.
        lookup_tables: ?noreturn,
    ) Instruction.InstructionCompileError!Message {
        comptime std.debug.assert(lookup_tables == null);

        const account_keys: []const Pubkey, const counts: AccountKindCounts = blk: {
            var compiled_keys = try compileKeys(allocator, payer, instructions);
            defer compiled_keys.deinit(allocator);

            const counts = AccountKindCounts.count(compiled_keys.values()) orelse
                return error.TooManyKeys;

            const account_keys = try allocator.dupe(Pubkey, compiled_keys.keys());
            errdefer allocator.free(account_keys);

            break :blk .{ account_keys, counts };
        };
        errdefer allocator.free(account_keys);

        const tx_instructions = try Instruction.compileList(
            allocator,
            instructions,
            account_keys,
        );
        errdefer {
            for (tx_instructions) |tx_inst| tx_inst.deinit(allocator);
            allocator.free(tx_instructions);
        }

        return .{
            .signature_count = counts.signature_count,
            .readonly_signed_count = counts.readonly_signed_count,
            .readonly_unsigned_count = counts.readonly_unsigned_count,
            .account_keys = account_keys,
            .recent_blockhash = recent_blockhash,
            .instructions = tx_instructions,
        };
    }

    pub fn isSigner(self: Message, index: usize) bool {
        return index < self.signature_count;
    }

    pub fn isWritable(self: Message, index: usize) bool {
        const is_readonly_signed =
            index < self.signature_count and
            index >= self.signature_count - self.readonly_signed_count;

        const is_readonly_unsigned = index >= self.account_keys.len - self.readonly_unsigned_count;

        return !(is_readonly_signed or is_readonly_unsigned);
    }

    /// Returns the serialized message as a bounded array.
    /// Returns an error if the message would exceed the maximum allowed transaction size.
    pub fn serializeBounded(
        self: Message,
        version: Version,
    ) !std.BoundedArray(u8, Transaction.MAX_BYTES) {
        var buf: std.BoundedArray(u8, Transaction.MAX_BYTES) = .{};
        try self.serialize(buf.writer(), version);
        return buf;
    }

    pub fn serialize(self: Message, writer: anytype, version: Version) !void {
        try writer.writeByte(self.signature_count);
        try writer.writeByte(self.readonly_signed_count);
        try writer.writeByte(self.readonly_unsigned_count);

        // WARN: Truncate okay if transaction is valid
        std.debug.assert(self.account_keys.len <= std.math.maxInt(u16));
        try leb.writeULEB128(writer, @as(u16, @intCast(self.account_keys.len)));
        for (self.account_keys) |id| try writer.writeAll(&id.data);

        try writer.writeAll(&self.recent_blockhash.data);

        // WARN: Truncate okay if transaction is valid
        std.debug.assert(self.instructions.len <= std.math.maxInt(u16));
        try leb.writeULEB128(writer, @as(u16, @intCast(self.instructions.len)));
        for (self.instructions) |instr| try sig.bincode.write(writer, instr, .{});

        // WARN: Truncate okay if transaction is valid
        if (version != Version.legacy) {
            std.debug.assert(self.address_lookups.len <= std.math.maxInt(u16));
            try leb.writeULEB128(writer, @as(u16, @intCast(self.address_lookups.len)));
            for (self.address_lookups) |alt| try sig.bincode.write(writer, alt, .{});
        }
    }

    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, version: Version) !Message {
        const signature_count = try reader.readByte();
        const readonly_signed_count = try reader.readByte();
        const readonly_unsigned_count = try reader.readByte();

        const account_keys = try allocator.alloc(Pubkey, try leb.readULEB128(u16, reader));
        errdefer sig.bincode.free(allocator, account_keys);
        for (account_keys) |*id| id.* = .{ .data = try reader.readBytesNoEof(Pubkey.SIZE) };

        const recent_blockhash: Hash = .{ .data = try reader.readBytesNoEof(Hash.SIZE) };

        const instructions = try allocator.alloc(Instruction, try leb.readULEB128(u16, reader));
        errdefer sig.bincode.free(allocator, instructions);
        for (instructions) |*instr| instr.* = try sig.bincode.read(allocator, Instruction, reader, .{});

        const address_lookups_len = if (version == .legacy) 0 else try leb.readULEB128(u16, reader);
        const address_lookups = try allocator.alloc(AddressLookup, address_lookups_len);
        errdefer sig.bincode.free(allocator, address_lookups);
        for (address_lookups) |*alt| alt.* = try sig.bincode.read(allocator, AddressLookup, reader, .{});

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

    pub fn validate(self: Message) !void {
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

    /// Return the blake3 hash of the pre-serialized message.
    pub fn hash(serialized_message: []const u8) Hash {
        var hasher = Blake3.init(.{});
        hasher.update("solana-tx-message-v1");
        hasher.update(serialized_message);
        var the_hash: Hash = .{ .data = undefined };
        hasher.final(&the_hash.data);
        return the_hash;
    }

    pub fn getSigningKeypairPosition(self: Message, pubkey: Pubkey) ?usize {
        const signed_keys = self.account_keys[0..self.signature_count];
        return for (signed_keys, 0..) |signed_key, i| {
            if (pubkey.equals(&signed_key)) break i;
        } else null;
    }
};

pub const Instruction = struct {
    /// Index into the transactions account_keys array
    program_index: u8,
    /// Index into the concatenation of the transactions account_keys array,
    /// writable lookup results, and readable lookup results
    account_indexes: []const u8,
    /// Serialized program instruction.
    data: []const u8,

    pub const @"!bincode-config:account_indexes" = shortVecConfig([]const u8);
    pub const @"!bincode-config:data" = shortVecConfig([]const u8);

    pub fn deinit(self: Instruction, allocator: std.mem.Allocator) void {
        allocator.free(self.account_indexes);
        allocator.free(self.data);
    }

    pub fn clone(self: *const Instruction, allocator: std.mem.Allocator) !Instruction {
        const account_indexes = try allocator.dupe(u8, self.account_indexes);
        errdefer allocator.free(account_indexes);
        return .{
            .program_index = self.program_index,
            .account_indexes = account_indexes,
            .data = try allocator.dupe(u8, self.data),
        };
    }

    pub const InstructionCompileError = error{
        MissingProgramIndex,
        MissingKeys,
        TooManyKeys,
    } || std.mem.Allocator.Error;

    pub fn initCompile(
        allocator: std.mem.Allocator,
        inst: sig.core.Instruction,
        keys: []const Pubkey,
    ) InstructionCompileError!Instruction {
        const program_index = blk: {
            const index = inst.program_id.indexIn(keys) orelse return error.MissingProgramIndex;
            break :blk std.math.cast(u8, index) orelse return error.TooManyKeys;
        };

        const data = try allocator.dupe(u8, inst.data);
        errdefer allocator.free(data);

        const account_indexes = try allocator.alloc(u8, inst.accounts.len);
        errdefer allocator.free(account_indexes);
        for (account_indexes, inst.accounts) |*account_idx, account| {
            const key_pos = account.pubkey.indexIn(keys) orelse return error.MissingKeys;
            account_idx.* = std.math.cast(u8, key_pos) orelse return error.TooManyKeys;
        }

        return .{
            .program_index = program_index,
            .account_indexes = account_indexes,
            .data = data,
        };
    }

    pub fn compileList(
        allocator: std.mem.Allocator,
        instructions: []const sig.core.Instruction,
        keys: []const Pubkey,
    ) InstructionCompileError![]const Instruction {
        const compiled_insts = try allocator.alloc(Instruction, instructions.len);
        errdefer allocator.free(compiled_insts);
        for (compiled_insts, instructions, 0..) |*compiled, inst, i| {
            errdefer for (compiled_insts[0..i]) |prev| prev.deinit(allocator);
            compiled.* = try initCompile(allocator, inst, keys);
        }
        return compiled_insts;
    }
};

pub const AddressLookup = struct {
    /// Address of the lookup table
    table_address: Pubkey,
    /// List of indexes used to load writable account ids
    writable_indexes: []const u8,
    /// List of indexes used to load readonly account ids
    readonly_indexes: []const u8,

    pub const @"!bincode-config:writable_indexes" = shortVecConfig([]const u8);
    pub const @"!bincode-config:readonly_indexes" = shortVecConfig([]const u8);

    pub fn deinit(self: AddressLookup, allocator: std.mem.Allocator) void {
        allocator.free(self.writable_indexes);
        allocator.free(self.readonly_indexes);
    }

    pub fn clone(self: *const AddressLookup, allocator: std.mem.Allocator) !AddressLookup {
        const writable_indexes = try allocator.dupe(u8, self.writable_indexes);
        errdefer allocator.free(writable_indexes);
        return .{
            .table_address = self.table_address,
            .writable_indexes = writable_indexes,
            .readonly_indexes = try allocator.dupe(u8, self.readonly_indexes),
        };
    }
};

const KeyMetaMap = std.AutoArrayHashMapUnmanaged(Pubkey, SignerWritableFlags);

const SignerWritableFlags = packed struct(u2) {
    writable: bool,
    signer: bool,

    pub const UNSIGNED_READONLY: SignerWritableFlags = .{
        .signer = false,
        .writable = false,
    };

    /// Orders such that a list of these flags is ordered like so:
    /// ```
    /// {
    ///      signer and  writable,
    ///      signer and !writable,
    ///     !signer and  writable,
    ///     !signer and !writable
    /// }
    /// ```
    pub fn order(self: SignerWritableFlags, other: SignerWritableFlags) std.math.Order {
        const a: u2 = @bitCast(self);
        const b: u2 = @bitCast(other);
        return std.math.order(a, b).invert();
    }
    comptime {
        std.debug.assert(order(
            .{ .writable = true, .signer = true },
            .{ .writable = false, .signer = true },
        ) == .lt);
        std.debug.assert(order(
            .{ .writable = false, .signer = true },
            .{ .writable = true, .signer = false },
        ) == .lt);
        std.debug.assert(order(
            .{ .writable = true, .signer = false },
            .{ .writable = false, .signer = false },
        ) == .lt);
    }
};

const AccountKindCounts = struct {
    signature_count: u8,
    readonly_signed_count: u8,
    readonly_unsigned_count: u8,

    /// Returns null on overflow.
    pub fn count(compiled_meta: []const SignerWritableFlags) ?AccountKindCounts {
        var required_signed: usize = 0;
        var readonly_signed: usize = 0;
        var readonly_unsigned: usize = 0;

        for (compiled_meta) |meta| {
            required_signed += @intFromBool(meta.signer);
            readonly_signed += @intFromBool(meta.signer and !meta.writable);
            readonly_unsigned += @intFromBool(!meta.signer and !meta.writable);
        }

        return .{
            .signature_count = std.math.cast(u8, required_signed) orelse return null,
            .readonly_signed_count = std.math.cast(u8, readonly_signed) orelse return null,
            .readonly_unsigned_count = std.math.cast(u8, readonly_unsigned) orelse return null,
        };
    }
};

/// Returns a map with all of the keys in `instructions`, and `maybe_payer`.
/// Sorted with `sortCompiledKeys` - see its doc comment for commentary on
/// the ordering of the keys.
fn compileKeys(
    allocator: std.mem.Allocator,
    maybe_payer: ?Pubkey,
    instructions: []const sig.core.Instruction,
) std.mem.Allocator.Error!KeyMetaMap {
    var key_meta_map: KeyMetaMap = .{};
    defer key_meta_map.deinit(allocator);

    for (instructions) |ix| {
        try key_meta_map.ensureUnusedCapacity(allocator, 1 + ix.accounts.len);

        {
            const gop = key_meta_map.getOrPutAssumeCapacity(ix.program_id);
            const meta = gop.value_ptr;
            if (!gop.found_existing) meta.* = SignerWritableFlags.UNSIGNED_READONLY;
        }

        for (ix.accounts) |account_meta| {
            const gop = key_meta_map.getOrPutAssumeCapacity(account_meta.pubkey);
            const meta = gop.value_ptr;
            if (!gop.found_existing) meta.* = SignerWritableFlags.UNSIGNED_READONLY;
            meta.signer = meta.signer or account_meta.is_signer;
            meta.writable = meta.writable or account_meta.is_writable;
        }
    }

    if (maybe_payer) |payer| {
        const gop = try key_meta_map.getOrPut(allocator, payer);
        const meta = gop.value_ptr;
        if (!gop.found_existing) meta.* = SignerWritableFlags.UNSIGNED_READONLY;
        meta.signer = true;
        meta.writable = true;
    }

    sortCompiledKeys(&key_meta_map, maybe_payer);
    return key_meta_map.move();
}

/// Sorts the map so that entries are ordered first by their `is_signer` and `is_writable` flags,
/// resulting in four groups `[signer & writable, signer, writable, neither]`, and then within each
/// of the four groups, entries will be sorted by their pubkeys, resulting in an absolute and
/// deterministic ordering.
fn sortCompiledKeys(
    key_meta_map: *KeyMetaMap,
    /// This is a pubkey asserted to be in the map, and will be sorted as the first entry.
    maybe_payer: ?Pubkey,
) void {
    if (maybe_payer) |payer| {
        std.debug.assert(key_meta_map.contains(payer));
    }

    const SortCtx = struct {
        key_meta_map: *const KeyMetaMap,
        payer: ?Pubkey,

        pub fn lessThan(
            ctx: @This(),
            a_index: usize,
            b_index: usize,
        ) bool {
            const a_key = ctx.key_meta_map.keys()[a_index];
            const a_value = ctx.key_meta_map.values()[a_index];

            const b_key = ctx.key_meta_map.keys()[b_index];
            const b_value = ctx.key_meta_map.values()[b_index];

            if (ctx.payer) |payer| {
                const a_is_payer = payer.equals(&a_key);
                const b_is_payer = payer.equals(&b_key);
                if (a_is_payer or b_is_payer) {
                    std.debug.assert(a_is_payer != b_is_payer); // weird sort bug?
                }
                if (a_is_payer) return true;
                if (b_is_payer) return false;
            }

            const ab_order = a_value.order(b_value).differ() orelse a_key.order(b_key);
            return ab_order == .lt;
        }
    };

    const sort_ctx: SortCtx = .{
        .key_meta_map = key_meta_map,
        .payer = maybe_payer,
    };

    key_meta_map.sort(sort_ctx);
}

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

test "verify and hash transaction" {
    try transaction_legacy_example.as_struct.verify();
    const hash = try transaction_legacy_example.as_struct.verifyAndHashMessage();
    try std.testing.expectEqual(
        try Hash.parseBase58String("FjoeKaxTd3J7xgt9vHMpuQb7j192weaEP3yMa1ntfQNo"),
        hash,
    );

    try std.testing.expectError(
        error.SignatureVerificationFailed,
        transaction_v0_example.as_struct.verify(),
    );
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        transaction_v0_example.as_struct.verifyAndHashMessage(),
    );
}
