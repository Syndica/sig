pub const std = @import("std");
pub const sig = @import("../sig.zig");
pub const core = @import("lib.zig");

const Hash = core.hash.Hash;
const Transaction = core.transaction.Transaction;
const CheckedReader = sig.utils.io.CheckedReader;

pub const Entry = struct {
    /// The number of hashes since the previous Entry ID.
    num_hashes: u64,

    /// The SHA-256 hash `num_hashes` after the previous Entry ID.
    hash: Hash,

    /// An unordered list of transactions that were observed before the Entry ID was
    /// generated. They may have been observed before a previous Entry ID but were
    /// pushed back into this list to ensure deterministic interpretation of the ledger.
    transactions: std.ArrayListUnmanaged(Transaction),

    pub fn isTick(self: Entry) bool {
        return self.transactions.items.len == 0;
    }

    pub fn deinit(self: Entry, allocator: std.mem.Allocator) void {
        for (self.transactions.items) |tx| tx.deinit(allocator);
        allocator.free(self.transactions.allocatedSlice());
    }

    pub fn readFromSlice(allocator: std.mem.Allocator, slice: []const u8) !Entry {
        var reader = CheckedReader.init(slice);
        return try Entry.deserialize(allocator, &reader);
    }

    pub fn serialize(self: Entry, writer: anytype) !void {
        try writer.writeInt(u64, self.num_hashes, std.builtin.Endian.little);
        try writer.writeAll(&self.hash.data);
        try writer.writeInt(usize, self.transactions.items.len, std.builtin.Endian.little);
        for (self.transactions.items) |tx| try tx.serialize(writer);
    }

    pub fn deserialize(allocator: std.mem.Allocator, reader: *CheckedReader) !Entry {
        const num_hashes = try reader.readInt(u64, std.builtin.Endian.little);
        const hash = .{ .data = (try reader.readBytes(Hash.size))[0..Hash.size].* };
        const transactions = try allocator.alloc(Transaction, try reader.readInt(usize, .little));
        errdefer {
            for (transactions) |tx| tx.deinit(allocator);
            allocator.free(transactions);
        }
        for (transactions) |*transaction|
            transaction.* = try Transaction.deserialize(allocator, reader);
        return .{
            .num_hashes = num_hashes,
            .hash = hash,
            .transactions = .{
                .items = transactions,
                .capacity = transactions.len,
            },
        };
    }
};

test "Entry serialization and deserialization" {
    const allocator = std.testing.allocator;

    const expected_struct = test_entry.as_struct;
    const expected_bytes = test_entry.as_bytes;

    const actual_buffer = try allocator.alloc(u8, expected_bytes.len);
    defer allocator.free(actual_buffer);
    var actual_fbs = std.io.fixedBufferStream(actual_buffer);
    try expected_struct.serialize(actual_fbs.writer());
    try std.testing.expectEqualSlices(u8, &expected_bytes, actual_fbs.getWritten());

    var actual_reader = CheckedReader.init(&expected_bytes);
    const actual_struct = try Entry.deserialize(allocator, &actual_reader);
    defer actual_struct.deinit(allocator);
    try std.testing.expect(sig.utils.types.eql(expected_struct, actual_struct));
}

pub const test_entry = struct {
    var txns = [_]Transaction{
        core.transaction.transaction_v0_example.as_struct,
        core.transaction.transaction_v0_example.as_struct,
    };

    pub const as_struct = Entry{
        .num_hashes = 149218308,
        .hash = core.Hash
            .parseBase58String("G8T3smgLc4XavAtxScD3u4FTAqPtwbFCEJKwJbfoECcd") catch unreachable,
        .transactions = .{
            .items = txns[0..2],
            .capacity = 2,
        },
    };

    pub const as_bytes = [_]u8{
        4,   228, 228, 8,   0,   0,   0,   0,   224, 199, 210, 235, 148, 143, 98,  241, 248, 45,
        140, 115, 214, 164, 132, 17,  95,  89,  221, 166, 5,   158, 5,   121, 181, 80,  48,  103,
        173, 21,  40,  70,  2,   0,   0,   0,   0,   0,   0,   0,   2,   81,  7,   106, 50,  99,
        54,  99,  92,  187, 47,  10,  170, 102, 132, 42,  25,  4,   26,  67,  106, 76,  132, 119,
        57,  38,  159, 7,   243, 132, 127, 236, 31,  83,  124, 56,  140, 54,  239, 100, 65,  111,
        8,   246, 103, 155, 246, 108, 196, 95,  231, 253, 121, 109, 53,  222, 96,  249, 211, 168,
        197, 148, 38,  209, 4,   184, 105, 238, 157, 236, 93,  219, 197, 154, 48,  106, 71,  230,
        220, 228, 253, 4,   34,  174, 202, 164, 57,  144, 240, 13,  183, 169, 164, 90,  77,  21,
        133, 150, 138, 9,   130, 196, 7,   48,  65,  73,  204, 64,  157, 104, 93,  54,  46,  185,
        1,   192, 88,  55,  179, 181, 207, 170, 11,  183, 143, 104, 116, 71,  4,   128, 39,  12,
        102, 2,   236, 88,  117, 221, 34,  125, 55,  183, 193, 174, 21,  99,  70,  167, 52,  227,
        254, 241, 14,  239, 13,  172, 158, 81,  254, 134, 30,  78,  35,  15,  168, 79,  73,  211,
        242, 100, 122, 21,  163, 216, 62,  58,  230, 205, 163, 112, 95,  100, 134, 113, 98,  129,
        164, 240, 184, 157, 4,   34,  55,  72,  89,  113, 179, 97,  58,  235, 71,  20,  83,  42,
        196, 46,  189, 136, 194, 90,  249, 14,  154, 144, 141, 234, 253, 148, 146, 168, 110, 10,
        237, 82,  157, 190, 248, 20,  215, 105, 1,   100, 2,   1,   3,   32,  104, 232, 42,  254,
        46,  48,  104, 89,  101, 211, 253, 161, 65,  155, 204, 89,  126, 187, 180, 191, 60,  59,
        88,  119, 106, 20,  194, 80,  11,  200, 76,  0,   1,   8,   65,  203, 149, 184, 2,   85,
        213, 101, 44,  13,  181, 13,  65,  128, 17,  94,  229, 31,  215, 47,  49,  72,  57,  158,
        144, 193, 224, 205, 241, 120, 78,  5,   1,   3,   5,   7,   90,  0,   2,   81,  7,   106,
        50,  99,  54,  99,  92,  187, 47,  10,  170, 102, 132, 42,  25,  4,   26,  67,  106, 76,
        132, 119, 57,  38,  159, 7,   243, 132, 127, 236, 31,  83,  124, 56,  140, 54,  239, 100,
        65,  111, 8,   246, 103, 155, 246, 108, 196, 95,  231, 253, 121, 109, 53,  222, 96,  249,
        211, 168, 197, 148, 38,  209, 4,   184, 105, 238, 157, 236, 93,  219, 197, 154, 48,  106,
        71,  230, 220, 228, 253, 4,   34,  174, 202, 164, 57,  144, 240, 13,  183, 169, 164, 90,
        77,  21,  133, 150, 138, 9,   130, 196, 7,   48,  65,  73,  204, 64,  157, 104, 93,  54,
        46,  185, 1,   192, 88,  55,  179, 181, 207, 170, 11,  183, 143, 104, 116, 71,  4,   128,
        39,  12,  102, 2,   236, 88,  117, 221, 34,  125, 55,  183, 193, 174, 21,  99,  70,  167,
        52,  227, 254, 241, 14,  239, 13,  172, 158, 81,  254, 134, 30,  78,  35,  15,  168, 79,
        73,  211, 242, 100, 122, 21,  163, 216, 62,  58,  230, 205, 163, 112, 95,  100, 134, 113,
        98,  129, 164, 240, 184, 157, 4,   34,  55,  72,  89,  113, 179, 97,  58,  235, 71,  20,
        83,  42,  196, 46,  189, 136, 194, 90,  249, 14,  154, 144, 141, 234, 253, 148, 146, 168,
        110, 10,  237, 82,  157, 190, 248, 20,  215, 105, 1,   100, 2,   1,   3,   32,  104, 232,
        42,  254, 46,  48,  104, 89,  101, 211, 253, 161, 65,  155, 204, 89,  126, 187, 180, 191,
        60,  59,  88,  119, 106, 20,  194, 80,  11,  200, 76,  0,   1,   8,   65,  203, 149, 184,
        2,   85,  213, 101, 44,  13,  181, 13,  65,  128, 17,  94,  229, 31,  215, 47,  49,  72,
        57,  158, 144, 193, 224, 205, 241, 120, 78,  5,   1,   3,   5,   7,   90,  0,
    };
};
