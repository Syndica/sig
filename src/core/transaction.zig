const std = @import("std");
const shortvec_config = @import("../utils/shortvec.zig").shortvec_config;
const Signature = @import("signature.zig").Signature;
const Pubkey = @import("pubkey.zig").Pubkey;
const Hash = @import("hash.zig").Hash;

pub const Transaction = struct {
    signatures: []Signature,
    message: Message,

    pub const @"!bincode-config:signatures" = shortvec_config;
};

pub const Message = struct {
    header: MessageHeader,
    account_keys: []Pubkey,
    recent_blockhash: Hash,
    instructions: []CompiledInstruction,

    pub const @"!bincode-config:account_keys" = shortvec_config;
    pub const @"!bincode-config:instructions" = shortvec_config;
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

    pub const @"!bincode-config:accounts" = shortvec_config;
    pub const @"!bincode-config:data" = shortvec_config;
};
