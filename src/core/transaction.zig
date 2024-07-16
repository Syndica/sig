const std = @import("std");
const sig = @import("../lib.zig");

const Signature = sig.core.Signature;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const ShortVecConfig = sig.bincode.shortvec.ShortVecConfig;

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

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
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

    pub fn deinit(self: *CompiledInstruction, allocator: std.mem.Allocator) void {
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
