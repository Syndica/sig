const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

pub const GetTransaction = struct {
    /// Transaction signature, as base-58 encoded string
    signature: Signature,
    config: ?struct {
        /// processed is not supported.
        commitment: ?enum { confirmed, finalized },
        /// Set the max transaction version to return in responses.
        /// If the requested transaction is a higher version, an error will be returned.
        /// If this parameter is omitted, only legacy transactions will be returned,
        /// and any versioned transaction will prompt the error.
        max_supported_transaction_version: ?u8,
        /// Encoding for the returned Transaction
        /// jsonParsed encoding attempts to use program-specific state parsers to return
        /// more human-readable and explicit data in the transaction.message.instructions
        /// list. If jsonParsed is requested but a parser cannot be found, the instruction
        /// falls back to regular JSON encoding (accounts, data, and programIdIndex fields).
        encoding: ?enum { json, jsonParsed, base64, base58 },
    },

    pub const Response = struct {
        /// the slot this transaction was processed in
        slot: Slot,
        /// Transaction object, either in JSON format or encoded binary data, depending on encoding parameter
        transaction: void,
        /// estimated production time, as Unix timestamp (seconds since the Unix epoch) of when the transaction was processed. null if not available
        blocktime: ?i64,
        /// transaction status metadata object:
        meta: void,
        /// Transaction version. Undefined if maxSupportedTransactionVersion is not set in request params.
        version: union(enum) { legacy, version: u8, not_defined },
    };
};
