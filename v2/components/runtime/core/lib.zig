const lib = @import("lib");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("instruction.zig");
        _ = @import("rent_collector.zig");
        _ = @import("time.zig");
        _ = @import("transaction.zig");
        _ = @import("transaction_error.zig");
    }
}

pub const epoch_schedule = lib.solana.epoch_schedule;
pub const features = lib.solana.features;
pub const hash = lib.solana.hash;
pub const instruction = @import("instruction.zig");
pub const pubkey = lib.solana.pubkey;
pub const rent_collector = @import("rent_collector.zig");
pub const signature = lib.solana.signature;
pub const time = @import("time.zig");
pub const transaction = @import("transaction.zig");
pub const transaction_error = @import("transaction_error.zig");

pub const EpochSchedule = epoch_schedule.EpochSchedule;
pub const FeatureSet = features.Set;
pub const Hash = hash.Hash;
pub const Instruction = instruction.Instruction;
pub const Pubkey = pubkey.Pubkey;
pub const RentCollector = rent_collector.RentCollector;
pub const Signature = signature.Signature;
pub const Transaction = transaction.Transaction;
pub const TransactionError = transaction_error.TransactionError;

pub const Epoch = time.Epoch;
pub const Slot = time.Slot;
