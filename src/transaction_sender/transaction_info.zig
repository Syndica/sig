const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Transaction = sig.core.transaction.Transaction;
const Instant = sig.time.Instant;

const PACKET_DATA_SIZE = sig.net.packet.PACKET_DATA_SIZE;

/// TransactionInfo is a wrapper around a transaction that includes additional
/// information needed to send the transaction, track retries and timeouts, etc.
pub const TransactionInfo = struct {
    signature: Signature,
    wire_transaction: [sig.net.packet.PACKET_DATA_SIZE]u8,
    wire_transaction_size: usize,
    last_valid_block_height: u64,
    durable_nonce_info: ?struct { Pubkey, Hash },
    max_retries: ?usize,
    retries: usize,
    last_sent_time: ?Instant,

    pub fn new(
        transaction: Transaction,
        last_valid_block_height: u64,
        durable_nonce_info: ?struct { Pubkey, Hash },
        max_retries: ?usize,
    ) !TransactionInfo {
        const signature = transaction.signatures[0];
        var transaction_info = TransactionInfo{
            .signature = signature,
            .wire_transaction = undefined,
            .wire_transaction_size = 0,
            .last_valid_block_height = last_valid_block_height,
            .durable_nonce_info = durable_nonce_info,
            .max_retries = max_retries,
            .retries = 0,
            .last_sent_time = null,
        };
        const written = try sig.bincode.writeToSlice(&transaction_info.wire_transaction, transaction, .{});
        transaction_info.wire_transaction_size = written.len;
        return transaction_info;
    }
};
