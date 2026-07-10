const std = @import("std");
const solana = @import("solana.zig");
const collections = @import("collections.zig");
const ipc = @import("ipc.zig");
const util = @import("util.zig");
const accounts_db = @import("accounts_db.zig");

const VersionedTransaction = solana.transaction.VersionedTransaction;
const VersionedMessage = solana.transaction.VersionedMessage;
const MessageHeader = solana.transaction.MessageHeader;
const Signature = solana.transaction.Signature;
const Pubkey = solana.transaction.Pubkey;
const SliceReader = solana.transaction.SliceReader;

const readShortU16 = solana.transaction.readShortU16;

// This is a bit large currently because of the unrooted store
pub const scratch_buffer_size = 3 * 1024 * 1024 * 1024;

pub const TransactionPool = collections.SharedPool(TransactionRecord, 10_000);

pub const BlockPool = collections.SharedPool(Node, 1024);

/// Transction bytes plus their validatoes wire layout.
///
/// This struct itself is safe to share between processe. Consumers can construct transient
/// `TransactionView`s locally, avoidng needing to re-parse the transaction bytes.
///
/// The `Layout` struct is just a collection of offsets and lengths into the `payload` array.
/// The `payload` array is a copy of the transaction bytes, which are expected to be in wire format
/// (i.e., as they would be sent over the network).
pub const TransactionRecord = extern struct {
    layout: Layout,
    payload: [VersionedTransaction.MAX_BYTES]u8,

    /// Reusable metadata extracted while structurally validating a serialized
    /// transaction.
    ///
    /// Every offset is relative to the first byte of the transaction.
    ///
    /// This type contains no pointers or slices and can safely be stored in
    /// shared memory. Methods that access serialized fields therefore receive
    /// the transaction's backing storage explicitly.
    ///
    /// offsets to collections point to the first element, after the collection's
    /// shortvec length prefix.
    /// TODO: document the layout of the serialized transaction and how it relates to this struct.
    pub const Layout = extern struct {
        /// Number of serialized transaction bytes.
        payload_len: u16,

        /// First signature byte, after the signature-count shortvec.
        signatures_off: u16,

        /// First byte of the signed message.
        ///
        /// For v0 this includes the version-prefix byte.
        message_off: u16,

        /// Length of the complete signed message.
        message_len: u16,

        /// First static account key, after the account-key-count shortvec.
        static_keys_off: u16,

        /// First byte of the 32-byte recent blockhash.
        recent_blockhash_off: u16,

        /// First serialized instruction, after the instruction-count shortvec.
        instructions_off: u16,

        /// First serialized address-table lookup, after its count shortvec.
        ///
        /// For legacy transactions, the count is zero and this points to the
        /// end of the message.
        address_table_lookups_off: u16,

        version: VersionedMessage.VersionByte,

        signature_count: u8,
        static_key_count: u8,
        instruction_count: u8,
        address_table_lookup_count: u8,

        loaded_writeable_count: u8,
        loaded_readonly_count: u8,

        num_readonly_signed_accounts: u8,
        num_readonly_unsigned_accounts: u8,

        // TODO: Do we want padding for cacheline alignment?
    };

    pub const View = struct {
        layout: *const Layout,
        payload: []const u8,

        pub fn header(self: View) MessageHeader {
            return .{
                .num_required_signatures = self.layout.signature_count,
                .num_readonly_signed_accounts = self.layout.num_readonly_signed_accounts,
                .num_readonly_unsigned_accounts = self.layout.num_readonly_unsigned_accounts,
            };
        }

        pub fn loadedAddressCount(self: View) usize {
            return @as(
                usize,
                self.layout.loaded_writeable_count + self.layout.loaded_readonly_count,
            );
        }

        pub fn totalAccountCount(self: View) usize {
            return self.loadedAddressCount() + self.layout.static_key_count;
        }

        pub fn hasAddressTableLookups(self: View) bool {
            return self.layout.address_table_lookup_count != 0;
        }

        pub fn signatures(self: View) []const Signature {
            const offset: usize = self.layout.signatures_off;
            const count: usize = self.layout.signature_count;
            const byte_len = count * Signature.SIZE;

            std.debug.assert(offset + byte_len <= self.layout.payload_len);
            std.debug.assert(byte_len <= self.payload.len - offset);

            const ptr: [*]const Signature = @ptrCast(self.payload[offset..].ptr);

            return ptr[0..count];
        }

        pub fn messageBytes(self: View) []const u8 {
            const offset: usize = self.layout.message_off;
            const len: usize = self.layout.message_len;

            std.debug.assert(offset <= self.layout.payload_len);
            std.debug.assert(len <= self.payload.len - offset);

            return self.payload[offset..][0..len];
        }

        pub fn staticAccountKeys(self: View) []const Pubkey {
            const offset: usize = self.layout.static_keys_off;
            const count: usize = self.layout.static_key_count;
            const byte_len = count * Pubkey.SIZE;

            std.debug.assert(offset + byte_len <= self.layout.payload_len);
            std.debug.assert(byte_len <= self.payload.len - offset);

            const ptr: [*]const Pubkey = @ptrCast(self.payload[offset..].ptr);

            return ptr[0..count];
        }

        pub fn recentBlockhash(self: View) *const solana.transaction.Hash {
            const offset: usize = self.layout.recent_blockhash_off;
            const len: usize = solana.transaction.Hash.SIZE;

            std.debug.assert(offset + len <= self.layout.payload_len);
            std.debug.assert(len <= self.payload.len - offset);

            return @ptrCast(self.payload[offset..].ptr);
        }

        pub fn instructions(self: View) CompiledInstructionIter {
            return .{
                .reader = .{
                    .bytes = self.payload,
                    .pos = self.layout.instructions_off,
                },
                .remaining = self.layout.instruction_count,
            };
        }

        pub const CompiledInstructionIter = struct {
            reader: SliceReader,
            remaining: u8,

            pub fn next(
                self: *CompiledInstructionIter,
            ) VersionedTransaction.ParseError!?struct {
                program_id_index: u8,
                account_indexes: []const u8,
                data: []const u8,
            } {
                if (self.remaining == 0) return null;

                const program_id_index = try self.reader.readByte();

                const account_count = try readShortU16(&self.reader);
                const account_indexes = try self.reader.takeBytes(account_count);

                const data_len = try readShortU16(&self.reader);
                const data = try self.reader.takeBytes(data_len);

                self.remaining -= 1;

                return .{
                    .program_id_index = program_id_index,
                    .account_indexes = account_indexes,
                    .data = data,
                };
            }
        };

        pub fn addressTableLookups(self: View) AddressTableLookupIter {
            const offset: usize = self.layout.address_table_lookups_off;

            std.debug.assert(offset <= self.payload.len);

            return .{
                .reader = .{
                    .bytes = self.payload,
                    .pos = offset,
                },
                .remaining = self.layout.address_table_lookup_count,
            };
        }

        pub const AddressTableLookupIter = struct {
            reader: SliceReader,
            remaining: u8,

            pub fn next(
                self: *AddressTableLookupIter,
            ) VersionedTransaction.ParseError!?struct {
                account_key: *const Pubkey,
                writable_indexes: []const u8,
                readonly_indexes: []const u8,
            } {
                if (self.remaining == 0) return null;

                const account_key_bytes =
                    try self.reader.takeBytes(Pubkey.SIZE);
                const account_key: *const Pubkey =
                    @ptrCast(account_key_bytes.ptr);

                const writable_count = try readShortU16(&self.reader);
                const writable_indexes =
                    try self.reader.takeBytes(writable_count);

                const readonly_count = try readShortU16(&self.reader);
                const readonly_indexes =
                    try self.reader.takeBytes(readonly_count);

                self.remaining -= 1;

                return .{
                    .account_key = account_key,
                    .writable_indexes = writable_indexes,
                    .readonly_indexes = readonly_indexes,
                };
            }
        };
    };
};

/// NOTE: this is what we use for referencing blocks. This is equivalent to the block's index
/// our block mem pool. If you want what Agave calls the "Block ID", this is the merkle root of
/// the last fec set.
pub const BlockRef = BlockPool.ItemId;

// TODO: large values (e.g. Hashes) should probably live elsewhere in memory to keep tree
// traversal fast
// This could maybe be 24 bytes (u32 idx * 3, slot u64, last merkle root hash u32)
pub const Node = extern struct {
    parent: BlockRef.Optional = .null,
    child: BlockRef.Optional = .null,
    sibling: BlockRef.Optional = .null,
    /// this is null for blocks older than the bootstrap root. do not unwrap
    /// unless you are certain the block is not older than the bootstrap root
    slot: util.PackedOptional(solana.Slot, std.math.maxInt(solana.Slot)),
};

pub const ExecReqResponse = extern struct {
    // submission queue
    request_ring: RequestRing,

    // completion queue
    response_ring: ResponseRing,

    pub const RequestRing = ipc.Ring(256, ExecRequest);
    pub const ResponseRing = ipc.Ring(256, ExecResponse);

    pub fn init(self: *ExecReqResponse) void {
        self.request_ring.init();
        self.response_ring.init();
    }
};

pub const RequestKind = enum(u8) {
    txn_exec,
    txn_sig_verify,
};

pub const ExecRequest = extern struct {
    task_id: u64, // user-provided, arbitrary, for the caller's tracking

    request_kind: RequestKind,
    data: extern union {
        txn_exec: extern struct {
            block_idx: BlockRef,
            tx_idx: TransactionPool.ItemId,
            n_account_refs: u8,
            account_ref_buf: [128]accounts_db.AccountPool.AccountRef,
        },
        txn_sig_verify: extern struct {
            tx_idx: TransactionPool.ItemId,
        },
    },
};

pub const ExecResponse = extern struct {
    task_id: u64, // user-provided, arbitrary, for the caller's tracking

    request_kind: RequestKind,
    data: extern union {
        txn_exec: extern struct {
            block_idx: BlockRef,
            tx_idx: TransactionPool.ItemId,
            n_account_refs: u8,
            account_ref_buf: [128]accounts_db.AccountPool.AccountRef,
            result: TxExecResult,
        },
        txn_sig_verify: extern struct { success: bool },
    },
};

pub const TxExecResult = extern struct {
    success: bool,
};
