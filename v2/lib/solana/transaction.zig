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

    pub fn bincodeWrite(
        self: *const VersionedMessage,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        switch (self.*) {
            .legacy => |msg| try bincode.write(writer, msg),
            .v0 => |msg| {
                try writer.writeByte(1 << 7);
                try bincode.write(writer, msg);
            },
        }
    }

    pub fn computeHash(self: *const VersionedMessage) Hash {
        var buffer: [1232]u8 = undefined;
        var hashing: std.Io.Writer.Hashing(std.crypto.hash.Blake3) = .init(&buffer);
        hashing.hasher.update("solana-tx-message-v1");
        self.bincodeWrite(&hashing.writer) catch |err| switch (err) {
            error.WriteFailed => unreachable,
        };
        var result: Hash = .{ .data = undefined };
        hashing.hasher.final(&result.data);
        return result;
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

/// Equivalent to agave's `TransactionError`.
pub const Error = union(enum(u32)) {
    /// An account is already being processed in another transaction in a way
    /// that does not support parallelism
    account_in_use,

    /// A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference
    /// `Pubkey`s more than once but the message must contain a list with no duplicate keys
    account_loaded_twice,

    /// Attempt to debit an account but found no record of a prior credit.
    account_not_found,

    /// Attempt to load a program that does not exist
    program_account_not_found,

    /// The from `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction
    insufficient_funds_for_fee,

    /// This account may not be used to pay transaction fees
    invalid_account_for_fee,

    /// The bank has seen this transaction before. This can occur under normal operation
    /// when a UDP packet is duplicated, as a user error from a client not updating
    /// its `recent_blockhash`, or as a double-spend attack.
    already_processed,

    /// The bank has not seen the given `recent_blockhash` or the transaction is too old and
    /// the `recent_blockhash` has been discarded.
    blockhash_not_found,

    /// An error occurred while processing an instruction. The first element of the tuple
    /// indicates the instruction index in which the error occurred.
    instruction_error: InstructionErrorPayload,

    /// Loader call chain is too deep
    call_chain_too_deep,

    /// Transaction requires a fee but has no signature present
    missing_signature_for_fee,

    /// Transaction contains an invalid account reference
    invalid_account_index,

    /// Transaction did not pass signature verification
    signature_failure,

    /// This program may not be used for executing instructions
    invalid_program_for_execution,

    /// Transaction failed to sanitize accounts offsets correctly
    /// implies that account locks are not taken for this TX, and should
    /// not be unlocked.
    sanitize_failure,

    cluster_maintenance,

    /// Transaction processing left an account with an outstanding borrowed reference
    account_borrow_outstanding,

    /// Transaction would exceed max Block Cost Limit
    would_exceed_max_block_cost_limit,

    /// Transaction version is unsupported
    unsupported_version,

    /// Transaction loads a writable account that cannot be written
    invalid_writable_account,

    /// Transaction would exceed max account limit within the block
    would_exceed_max_account_cost_limit,

    /// Transaction would exceed account data limit within the block
    would_exceed_account_data_block_limit,

    /// Transaction locked too many accounts
    too_many_account_locks,

    /// Address lookup table not found
    address_lookup_table_not_found,

    /// Attempted to lookup addresses from an account owned by the wrong program
    invalid_address_lookup_table_owner,

    /// Attempted to lookup addresses from an invalid account
    invalid_address_lookup_table_data,

    /// Address table lookup uses an invalid index
    invalid_address_lookup_table_index,

    /// Transaction leaves an account with a lower balance than rent-exempt minimum
    invalid_rent_paying_account,

    /// Transaction would exceed max Vote Cost Limit
    would_exceed_max_vote_cost_limit,

    /// Transaction would exceed total account data limit
    would_exceed_account_data_total_limit,

    /// Transaction contains a duplicate instruction that is not allowed
    duplicate_instruction: u8,

    /// Transaction results in an account with insufficient funds for rent
    insufficient_funds_for_rent: extern struct {
        account_index: u8,
    },

    /// Transaction exceeded max loaded accounts data size cap
    max_loaded_accounts_data_size_exceeded,

    /// LoadedAccountsDataSizeLimit set for transaction must be greater than 0.
    invalid_loaded_accounts_data_size_limit,

    /// Sanitized transaction differed before/after feature activation. Needs to be resanitized.
    resanitization_needed,

    /// Program execution is temporarily restricted on an account.
    program_execution_temporarily_restricted: extern struct {
        account_index: u8,
    },

    /// The total balance before the transaction does not equal the total balance after the transaction
    unbalanced_transaction,

    /// Program cache hit max limit.
    program_cache_hit_max_limit,

    /// Commit cancelled internally.
    commit_cancelled,

    pub const InstructionErrorPayload = struct {
        index: u8,
        code: InstructionError,

        pub fn pack(self: InstructionErrorPayload) InstructionErrorPayload.Extern {
            return .pack(self);
        }

        pub fn unpack(value: InstructionErrorPayload.Extern) InstructionErrorPayload {
            return value.unpack();
        }

        pub const Extern = extern struct {
            index: u8,
            code: InstructionError.Extern,

            pub fn pack(value: InstructionErrorPayload) InstructionErrorPayload.Extern {
                return .{
                    .index = value.index,
                    .code = value.code.pack(),
                };
            }

            pub fn unpack(self: InstructionErrorPayload.Extern) InstructionErrorPayload {
                return .{
                    .index = self.index,
                    .code = self.code.unpack(),
                };
            }
        };
    };

    pub fn read(
        /// `std.Io.Reader` or equivalent interface.
        r: anytype,
    ) (std.Io.Reader.Error || std.Io.Reader.TakeEnumError)!Error {
        const zone = tracy.Zone.init(@src(), .{ .name = "TransactionError.read" });
        defer zone.deinit();

        const Tag = @typeInfo(Error).@"union".tag_type.?;
        const tag = try r.takeEnum(Tag, .little);
        return switch (tag) {
            .instruction_error => .{ .instruction_error = .{
                .index = try r.takeByte(),
                .code = try .read(r),
            } },
            .duplicate_instruction => .{ .duplicate_instruction = try r.takeByte() },
            .insufficient_funds_for_rent => .{
                .insufficient_funds_for_rent = .{
                    .account_index = try r.takeByte(),
                },
            },
            .program_execution_temporarily_restricted => .{
                .program_execution_temporarily_restricted = .{
                    .account_index = try r.takeByte(),
                },
            },
            inline else => |itag| itag,
        };
    }

    pub fn unpack(value: Extern) Error {
        return value.unpack();
    }

    pub fn pack(self: Error) Extern {
        return .pack(self);
    }

    pub const Extern = extern struct {
        pl: Payload,
        tag: Tag,

        pub fn pack(value: Error) Extern {
            const pl = switch (value) {
                .instruction_error => |ie| .{ .instruction_error = .pack(ie) },
                inline else => |pl, t| @unionInit(Payload, @tagName(t), pl),
            };
            return .{ .pl = pl, .tag = value };
        }

        pub fn unpack(value: Extern) Error {
            return switch (value.tag) {
                .instruction_error => |ie| .{ .instruction_error = .unpack(ie) },
                inline else => |itag| @unionInit(
                    Error,
                    @tagName(itag),
                    @field(value.pl, @tagName(itag)),
                ),
            };
        }

        pub const Tag = @typeInfo(Error).@"union".tag_type.?;
        pub const Payload = @Type(.{ .@"union" = .{
            .layout = .@"extern",
            .tag_type = null,
            .fields = fields: {
                var fields = @typeInfo(Error).@"union".fields[0..].*;

                const instr_err_field = &fields[@intFromEnum(Tag.instruction_error)];
                instr_err_field.type = InstructionErrorPayload.Extern;
                instr_err_field.alignment = @alignOf(instr_err_field.type);

                const copy = fields;
                break :fields &copy;
            },
            .decls = &.{},
        } });
    };
};

pub const InstructionError = union(enum(u32)) {
    /// XXX: Deprecated! Use CustomError instead!
    generic_error,

    /// The arguments provided to a program were invalid
    invalid_argument,

    /// An instruction's data contents were invalid
    invalid_instruction_data,

    /// An account's data contents was invalid
    invalid_account_data,

    /// An account's data was too small
    account_data_too_small,

    /// An account's balance was too small to complete the instruction
    insufficient_funds,

    /// The account did not have the expected program id
    incorrect_program_id,

    /// A signature was required but not found
    missing_required_signature,

    /// An initialize instruction was sent to an account that has already been initialized.
    account_already_initialized,

    /// An attempt to operate on an account that hasn't been initialized.
    uninitialized_account,

    /// Program's instruction lamport balance does not equal the balance after the instruction
    unbalanced_instruction,

    /// Program illegally modified an account's program id
    modified_program_id,

    /// Program spent the lamports of an account that doesn't belong to it
    external_account_lamport_spend,

    /// Program modified the data of an account that doesn't belong to it
    external_account_data_modified,

    /// Read-only account's lamports modified
    readonly_lamport_change,

    /// Read-only account's data was modified
    readonly_data_modified,

    /// An account was referenced more than once in a single instruction
    /// XXX: Deprecated, instructions can now contain duplicate accounts
    duplicate_account_index,

    /// Executable bit on account changed, but shouldn't have
    executable_modified,

    /// Rent_epoch account changed, but shouldn't have
    rent_epoch_modified,

    /// The instruction expected additional account keys
    /// XXX: #[deprecated(since = "2.1.0", note = "Use InstructionError::MissingAccount instead")]
    not_enough_account_keys,

    /// Program other than the account's owner changed the size of the account data
    account_data_size_changed,

    /// The instruction expected an executable account
    account_not_executable,

    /// Failed to borrow a reference to account data, already borrowed
    account_borrow_failed,

    /// Account data has an outstanding reference after a program's execution
    account_borrow_outstanding,

    /// The same account was multiply passed to an on-chain program's entrypoint, but the program
    /// modified them differently.  A program can only modify one instance of the account because
    /// the runtime cannot determine which changes to pick or how to merge them if both are modified
    duplicate_account_out_of_sync,

    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    custom: u32,

    /// The return value from the program was invalid.  Valid errors are either a defined builtin
    /// error value or a user-defined error in the lower 32 bits.
    invalid_error,

    /// Executable account's data was modified
    executable_data_modified,

    /// Executable account's lamports modified
    executable_lamport_change,

    /// Executable accounts must be rent exempt
    executable_account_not_rent_exempt,

    /// Unsupported program id
    unsupported_program_id,

    /// Cross-program invocation call depth too deep
    call_depth,

    /// An account required by the instruction is missing
    missing_account,

    /// Cross-program invocation reentrancy not allowed for this instruction
    reentrancy_not_allowed,

    /// Length of the seed is too long for address generation
    max_seed_length_exceeded,

    /// Provided seeds do not result in a valid address
    invalid_seeds,

    /// Failed to reallocate account data of this length
    invalid_realloc,

    /// Computational budget exceeded
    computational_budget_exceeded,

    /// Cross-program invocation with unauthorized signer or writable account
    privilege_escalation,

    /// Failed to create program execution environment
    program_environment_setup_failure,

    /// Program failed to complete
    program_failed_to_complete,

    /// Program failed to compile
    program_failed_to_compile,

    /// Account is immutable
    immutable,

    /// Incorrect authority provided
    incorrect_authority,

    /// Failed to serialize or deserialize account data
    borsh_io_error,

    /// An account does not have enough lamports to be rent-exempt
    account_not_rent_exempt,

    /// Invalid account owner
    invalid_account_owner,

    /// Program arithmetic overflowed
    arithmetic_overflow,

    /// Unsupported sysvar
    unsupported_sysvar,

    /// Illegal account owner
    illegal_owner,

    /// Accounts data allocations exceeded the maximum allowed per transaction
    max_accounts_data_allocations_exceeded,

    /// Max accounts exceeded
    max_accounts_exceeded,

    /// Max instruction trace length exceeded
    max_instruction_trace_length_exceeded,

    /// Builtin programs must consume compute units
    builtin_programs_must_consume_compute_units,
    // Note: For any new error added here an equivalent ProgramError and its
    // conversions must also be added

    pub fn read(
        /// `std.Io.Reader` or equivalent interface.
        r: anytype,
    ) (std.Io.Reader.Error || std.Io.Reader.TakeEnumError)!InstructionError {
        const zone = tracy.Zone.init(@src(), .{ .name = "InstructionError.read" });
        defer zone.deinit();

        const Tag = @typeInfo(InstructionError).@"union".tag_type.?;
        const tag = try r.takeEnum(Tag, .little);
        return switch (tag) {
            .custom => .{ .custom = try r.takeInt(u32, .little) },
            inline else => |itag| itag,
        };
    }

    pub fn unpack(value: Extern) InstructionError {
        return value.unpack();
    }

    pub fn pack(self: InstructionError) Extern {
        return .pack(self);
    }

    pub const Extern = extern struct {
        pl: Payload,
        tag: Tag,

        pub fn pack(value: InstructionError) Extern {
            const pl = switch (value) {
                inline else => |pl, t| @unionInit(Payload, @tagName(t), pl),
            };
            return .{ .pl = pl, .tag = value };
        }

        pub fn unpack(value: Extern) InstructionError {
            return switch (value.tag) {
                inline else => |itag| @unionInit(
                    InstructionError,
                    @tagName(itag),
                    @field(value.pl, @tagName(itag)),
                ),
            };
        }

        pub const Tag = @typeInfo(InstructionError).@"union".tag_type.?;
        pub const Payload = @Type(.{ .@"union" = .{
            .layout = .@"extern",
            .tag_type = null,
            .fields = @typeInfo(InstructionError).@"union".fields,
            .decls = &.{},
        } });
    };
};
