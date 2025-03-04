const std = @import("std");
const sig = @import("../../../sig.zig");

const BorrowedAccount = sig.runtime.BorrowedAccount;
const InstructionContext = sig.runtime.InstructionContext;
const InstructionError = sig.core.instruction.InstructionError;
const nonce = sig.runtime.nonce;
const Pubkey = sig.core.Pubkey;
const pubkey_utils = sig.runtime.pubkey_utils;
const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;
const Slot = sig.core.Slot;
const system_program = sig.runtime.program.system_program;
const SystemProgramError = system_program.Error;
const SystemProgramInstruction = system_program.Instruction;
const SysvarCache = sig.runtime.SysvarCache;
const sysvar = sig.runtime.sysvar;

pub const Instruction = @import("instruction.zig").Instruction;

pub const ID = sig.runtime.ids.ADDRESS_LOOKUP_TABLE_PROGRAM_ID;

pub const execute = @import("execute.zig").execute;

// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L30
/// The maximum number of addresses that a lookup table can hold
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

//https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L33
/// The serialized size of lookup table metadata
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L23
pub const COMPUTE_UNITS = 750;

const relax_authority_signer_check_for_lookup_table_creation = Pubkey.parseBase58String(
    "relax_authority_signer_check_for_lookup_table_creation",
) catch unreachable;
