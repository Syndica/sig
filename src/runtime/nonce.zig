const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const FeeCalculator = sig.runtime.sysvar.Fees.FeeCalculator;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/current.rs#L10-L11
const DURABLE_NONCE_HASH_PREFIX = "DURABLE_NONCE";

/// Current variants have durable nonce and blockhash domains separated.\
///
/// Must support `bincode` and `serializedSize` methods for writing to the account data.\
///
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/mod.rs#L12
pub const Versions = union(enum) {
    legacy: State,
    current: State,

    pub fn getState(self: Versions) State {
        switch (self) {
            .legacy => |state| return state,
            .current => |state| return state,
        }
    }
};

/// The state of a durable transaction nonce account.
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/current.rs#L71
pub const State = union(enum) {
    unintialized,
    initialized: Data,
};

/// Initialized data of a durable transaction nonce account
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/current.rs#L19
pub const Data = struct {
    /// Address of the account that signs transactions using the nonce account.
    authority: Pubkey,
    /// Durable nonce value derived from a valid previous blockhash.
    durable_nonce: Hash,
    /// The fee calculator associated with the blockhash.
    fee_calculator: FeeCalculator,

    pub fn init(
        authority: Pubkey,
        durable_nonce: Hash,
        lamports_per_signature: u64,
    ) Data {
        return .{
            .authority = authority,
            .durable_nonce = durable_nonce,
            .fee_calculator = .{ .lamports_per_signature = lamports_per_signature },
        };
    }
};

pub fn createDurableNonce(blockhash: Hash) Hash {
    return sig.runtime.tmp_utils.hashv(&.{ DURABLE_NONCE_HASH_PREFIX, &blockhash.data });
}
