const std = @import("std");
const sig = @import("../sig.zig");
const shared_transaction = @import("shared").core.transaction;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

pub const Version = shared_transaction.Version;
pub const Message = shared_transaction.Message;
pub const Instruction = shared_transaction.Instruction;
pub const AddressLookup = shared_transaction.AddressLookup;

pub const Transaction = struct {
    signatures: []const Signature,
    version: Version,
    msg: Message,

    pub const MAX_BYTES = shared_transaction.Transaction.MAX_BYTES;
    pub const MAX_SIGNATURES = shared_transaction.Transaction.MAX_SIGNATURES;
    pub const MAX_ACCOUNTS = shared_transaction.Transaction.MAX_ACCOUNTS;
    pub const MAX_INSTRUCTIONS = shared_transaction.Transaction.MAX_INSTRUCTIONS;
    pub const MAX_ADDRESS_LOOKUP_TABLES = shared_transaction.Transaction.MAX_ADDRESS_LOOKUP_TABLES;
    pub const VERSION_PREFIX = shared_transaction.Transaction.VERSION_PREFIX;
    pub const @"!bincode-config": sig.bincode.FieldConfig(Transaction) = .{
        .deserializer = deserialize,
        .serializer = serialize,
    };
    pub const EMPTY = fromShared(shared_transaction.Transaction.EMPTY);

    pub fn fromShared(tx: shared_transaction.Transaction) Transaction {
        return .{ .signatures = tx.signatures, .version = tx.version, .msg = tx.msg };
    }

    pub fn toShared(self: Transaction) shared_transaction.Transaction {
        return .{ .signatures = self.signatures, .version = self.version, .msg = self.msg };
    }

    pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
        self.toShared().deinit(allocator);
    }

    pub fn clone(self: Transaction, allocator: std.mem.Allocator) !Transaction {
        return fromShared(try self.toShared().clone(allocator));
    }

    pub fn validate(self: Transaction) !void {
        return self.toShared().validate();
    }

    pub fn serialize(writer: anytype, data: anytype, params: sig.bincode.Params) !void {
        return shared_transaction.Transaction.serialize(writer, data, params);
    }

    pub fn deserialize(
        limit_allocator: *sig.bincode.LimitAllocator,
        reader: anytype,
        params: sig.bincode.Params,
    ) !Transaction {
        return fromShared(try shared_transaction.Transaction.deserialize(
            limit_allocator,
            reader,
            params,
        ));
    }

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

    pub fn initRandom(
        allocator: std.mem.Allocator,
        random: std.Random,
        payer: ?std.crypto.sign.Ed25519.KeyPair,
    ) !Transaction {
        var seed: [32]u8 = undefined;
        random.bytes(&seed);
        const keypair = payer orelse
            try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        const signer = Pubkey.fromPublicKey(&keypair.public_key);

        const account_keys = try allocator.dupe(Pubkey, &.{
            signer,
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
        });
        errdefer allocator.free(account_keys);

        const data = try allocator.alloc(u8, random.intRangeAtMost(usize, 0, 256));
        errdefer allocator.free(data);
        random.bytes(data);

        const account_indexes = try allocator.dupe(u8, &.{ 0, 1 });
        errdefer allocator.free(account_indexes);

        const instructions = try allocator.dupe(Instruction, &.{.{
            .program_index = 2,
            .account_indexes = account_indexes,
            .data = data,
        }});
        errdefer allocator.free(instructions);

        const message = Message{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 1,
            .account_keys = account_keys,
            .recent_blockhash = Hash.initRandom(random),
            .instructions = instructions,
            .address_lookups = &.{},
        };

        return try initOwnedMessageWithSigningKeypairs(allocator, .v0, message, &.{keypair});
    }

    pub const InitOwnedMessageWithSigningKeypairsError = error{
        BadMessage,
        SigningError,
    } || std.mem.Allocator.Error;

    pub fn initOwnedMessageWithSigningKeypairs(
        allocator: std.mem.Allocator,
        version: Version,
        message: Message,
        keypairs: []const sig.identity.KeyPair,
    ) InitOwnedMessageWithSigningKeypairsError!Transaction {
        const msg_bytes_bounded = message.serializeBounded(version) catch return error.BadMessage;
        const msg_bytes = msg_bytes_bounded.constSlice();

        const signatures = try allocator.alloc(Signature, message.signature_count);
        errdefer allocator.free(signatures);

        const signing_keys = message.account_keys[0..message.signature_count];
        for (signing_keys, 0..) |key, i| {
            for (keypairs) |kp| {
                const public_key: Pubkey = .fromPublicKey(&kp.public_key);
                if (!key.equals(&public_key)) continue;
                const msg_signature = kp.sign(msg_bytes, null) catch return error.SigningError;
                signatures[i] = .fromSignature(msg_signature);
            }
        }

        return .{
            .signatures = signatures,
            .version = version,
            .msg = message,
        };
    }

    pub const VerifyError = error{
        NoSpaceLeft,
        NonCanonical,
        NotEnoughAccounts,
        SignatureVerificationFailed,
        SerializationFailed,
    };

    pub fn verify(self: Transaction) VerifyError!void {
        const serialized_message = self.msg.serializeBounded(self.version) catch
            return error.SerializationFailed;
        try self.verifySignatures(serialized_message.constSlice());
    }

    pub fn verifySignatures(self: Transaction, serialized_message: []const u8) VerifyError!void {
        if (self.msg.account_keys.len < self.signatures.len) return error.NotEnoughAccounts;

        sig.crypto.ed25519.verifyBatchOverSingleMessage(
            16,
            self.signatures,
            self.msg.account_keys[0..self.signatures.len],
            serialized_message,
        ) catch return error.SignatureVerificationFailed;
    }

    pub fn isSimpleVoteTransaction(
        self: *const Transaction,
        instructions: []const sig.runtime.InstructionInfo,
    ) bool {
        if (instructions.len != 1) return false;
        if (self.signatures.len == 0 or self.signatures.len > 2) return false;
        if (self.msg.address_lookups.len > 0) return false;

        return instructions[0].program_meta.pubkey.equals(&sig.runtime.program.vote.ID);
    }
};

pub fn isWritable(
    message: Message,
    index: usize,
    maybe_lookups: ?sig.replay.resolve_lookup.LookupTableAccounts,
    reserved_accounts: *const sig.core.ReservedAccounts,
) bool {
    const lookups = maybe_lookups orelse sig.replay.resolve_lookup.LookupTableAccounts{
        .writable = &.{},
        .readonly = &.{},
    };
    const pubkey = blk: {
        if (index < message.account_keys.len) {
            if (index >= message.signature_count) {
                if (index >= message.account_keys.len - message.readonly_unsigned_count) return false;
            } else {
                if (index >= message.signature_count - message.readonly_signed_count) return false;
            }
            break :blk message.account_keys[index];
        } else if (index < message.account_keys.len + lookups.writable.len) {
            break :blk lookups.writable[index - message.account_keys.len];
        } else {
            return false;
        }
    };

    const is_upgradeable_loader_present = blk: for ([_][]const Pubkey{
        message.account_keys,
        lookups.writable,
        lookups.readonly,
    }) |accounts| {
        for (accounts) |account_key|
            if (account_key.equals(&sig.runtime.program.bpf_loader.v3.ID))
                break :blk true;
    } else false;

    const is_key_called_as_program = for (message.instructions) |ixn| {
        if (ixn.program_index == index) break true;
    } else false;

    const is_reserved = reserved_accounts.map.contains(pubkey);
    const demote_program_id = is_key_called_as_program and !is_upgradeable_loader_present;
    return !(is_reserved or demote_program_id);
}

pub fn compileMessage(
    allocator: std.mem.Allocator,
    instructions: []const sig.core.Instruction,
    payer: ?Pubkey,
    recent_blockhash: Hash,
) Instruction.InstructionCompileError!Message {
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

const KeyMetaMap = sig.utils.collections.PubkeyMap(SignerWritableFlags);

const SignerWritableFlags = packed struct(u2) {
    writable: bool,
    signer: bool,

    pub const UNSIGNED_READONLY: SignerWritableFlags = .{
        .signer = false,
        .writable = false,
    };

    pub fn order(self: SignerWritableFlags, other: SignerWritableFlags) std.math.Order {
        const a: u2 = @bitCast(self);
        const b: u2 = @bitCast(other);
        return std.math.order(a, b).invert();
    }
};

const AccountKindCounts = struct {
    signature_count: u8,
    readonly_signed_count: u8,
    readonly_unsigned_count: u8,

    fn count(compiled_meta: []const SignerWritableFlags) ?AccountKindCounts {
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

fn sortCompiledKeys(key_meta_map: *KeyMetaMap, maybe_payer: ?Pubkey) void {
    if (maybe_payer) |payer| std.debug.assert(key_meta_map.contains(payer));

    const SortCtx = struct {
        key_meta_map: *const KeyMetaMap,
        payer: ?Pubkey,

        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
            const a_key = ctx.key_meta_map.keys()[a_index];
            const a_value = ctx.key_meta_map.values()[a_index];
            const b_key = ctx.key_meta_map.keys()[b_index];
            const b_value = ctx.key_meta_map.values()[b_index];

            if (ctx.payer) |payer| {
                const a_is_payer = payer.equals(&a_key);
                const b_is_payer = payer.equals(&b_key);
                if (a_is_payer or b_is_payer) std.debug.assert(a_is_payer != b_is_payer);
                if (a_is_payer) return true;
                if (b_is_payer) return false;
            }

            const ab_order = a_value.order(b_value).differ() orelse a_key.order(b_key);
            return ab_order == .lt;
        }
    };

    key_meta_map.sort(SortCtx{ .key_meta_map = key_meta_map, .payer = maybe_payer });
}

pub const transaction_legacy_example = struct {
    pub const as_struct = Transaction.fromShared(shared_transaction.transaction_legacy_example.as_struct);
    pub const as_bytes = shared_transaction.transaction_legacy_example.as_bytes;
};

pub const transaction_v0_example = struct {
    pub const as_struct = Transaction.fromShared(shared_transaction.transaction_v0_example.as_struct);
    pub const as_bytes = shared_transaction.transaction_v0_example.as_bytes;
};
