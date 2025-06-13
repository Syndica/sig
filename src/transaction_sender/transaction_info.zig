const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;
const Instant = std.time.Instant;
const Duration = sig.time.Duration;

/// TransactionInfo is a wrapper around a transaction that includes additional
/// information needed to send the transaction, track retries and timeouts, etc.
pub const TransactionInfo = struct {
    signature: Signature,
    wire_transaction: [sig.net.Packet.DATA_SIZE]u8,
    wire_transaction_size: usize,
    last_valid_block_height: u64,
    durable_nonce_info: ?struct { Pubkey, Hash },
    max_retries: ?usize,
    retries: usize,
    last_sent_time: ?Instant,

    pub fn init(
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
        const written = try sig.bincode.writeToSlice(
            &transaction_info.wire_transaction,
            transaction,
            .{},
        );
        transaction_info.wire_transaction_size = written.len;
        return transaction_info;
    }

    pub fn exceededMaxRetries(self: *const TransactionInfo, default_max_retries: ?usize) bool {
        const maybe_max_retries = self.max_retries orelse default_max_retries;
        if (maybe_max_retries) |max_retries| {
            if (self.retries >= max_retries) {
                return true;
            }
        }
        return false;
    }

    pub fn shouldRetry(self: *const TransactionInfo, wait_between_retries: Duration) bool {
        if (self.last_sent_time) |lst| {
            const now = sig.time.clock.sample();
            return now.since(lst) >= wait_between_retries.asNanos();
        }
        return true;
    }

    pub fn isExpired(self: *const TransactionInfo, current_block_height: u64) bool {
        return current_block_height > self.last_valid_block_height;
    }
};
