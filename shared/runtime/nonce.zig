const std = @import("std");
const sig = @import("../lib.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

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

    // [agave] https://github.com/anza-xyz/solana-sdk/blob/51e1da20ab83511563bd400cb448c2fee4ac4db6/nonce/src/state.rs#L104
    pub const SERIALIZED_SIZE = 80;

    pub fn getState(self: Versions) State {
        switch (self) {
            .legacy => |state| return state,
            .current => |state| return state,
        }
    }

    pub fn verify(
        self: Versions,
        durable_nonce: Hash,
    ) ?Data {
        switch (self) {
            .legacy => |_| return null,
            .current => |state| switch (state) {
                .uninitialized => return null,
                .initialized => |data| {
                    return if (durable_nonce.eql(data.durable_nonce)) data else null;
                },
            },
        }
    }

    pub fn upgrade(self: Versions) ?Versions {
        switch (self) {
            .legacy => |state| switch (state) {
                .uninitialized => return null,
                .initialized => |data| {
                    var new_data = data;
                    new_data.durable_nonce = initDurableNonceFromHash(data.durable_nonce);
                    return Versions{ .current = .{ .initialized = new_data } };
                },
            },
            .current => |_| return null,
        }
    }

    pub fn fromAccountData(account_data: []const u8) ?Versions {
        return sig.bincode.readFromSlice(
            sig.utils.allocators.failing.allocator(.{}), // no allocations in this type
            Versions,
            account_data,
            .{},
        ) catch null;
    }
};

/// The state of a durable transaction nonce account.
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/current.rs#L71
pub const State = union(enum) {
    uninitialized,
    initialized: Data,
};

/// Initialized data of a durable transaction nonce account
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/current.rs#L19
pub const Data = struct {
    /// Address of the account that signs transactions using the nonce account.
    authority: Pubkey,
    /// Durable nonce value derived from a valid previous blockhash.
    durable_nonce: Hash,
    /// The lamports per signature associated with the blockhash.
    lamports_per_signature: u64,

    pub fn init(
        authority: Pubkey,
        durable_nonce: Hash,
        lamports_per_signature: u64,
    ) Data {
        return .{
            .authority = authority,
            .durable_nonce = durable_nonce,
            .lamports_per_signature = lamports_per_signature,
        };
    }
};

pub fn initDurableNonceFromHash(blockhash: Hash) Hash {
    return .initMany(&.{ DURABLE_NONCE_HASH_PREFIX, &blockhash.data });
}
