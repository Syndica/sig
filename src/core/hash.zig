const std = @import("std");
const sig = @import("../sig.zig");
const base58 = @import("base58");

const BASE58_ENDEC = base58.Table.BITCOIN;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Slot = sig.core.time.Slot;

pub const SlotAndHash = struct {
    slot: Slot,
    hash: Hash,

    pub fn order(a: SlotAndHash, b: SlotAndHash) std.math.Order {
        if (a.slot == b.slot and a.hash.order(&b.hash) == .eq) {
            return .eq;
        } else if (a.slot < b.slot or a.slot == b.slot and (a.hash.order(&b.hash) == .lt)) {
            return .lt;
        } else if (a.slot > b.slot or a.slot == b.slot and (a.hash.order(&b.hash) == .gt)) {
            return .gt;
        } else {
            unreachable;
        }
    }

    pub fn equals(a: *const SlotAndHash, b: *const SlotAndHash) bool {
        return order(a, b) == .eq;
    }
};

pub const Hash = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;

    pub const ZEROES: Hash = .{ .data = .{0} ** SIZE };

    pub fn generateSha256Hash(bytes: []const u8) Hash {
        var data: [SIZE]u8 = undefined;
        Sha256.hash(bytes, &data, .{});
        return .{ .data = data };
    }

    pub fn extendAndHash(self: Hash, val: []const u8) Hash {
        var hasher = Sha256.init(.{});
        hasher.update(&self.data);
        hasher.update(val);
        return .{ .data = hasher.finalResult() };
    }

    pub fn eql(self: Hash, other: Hash) bool {
        const xx: @Vector(SIZE, u8) = self.data;
        const yy: @Vector(SIZE, u8) = other.data;
        return @reduce(.And, xx == yy);
    }

    pub fn order(self: *const Hash, other: *const Hash) std.math.Order {
        return for (self.data, other.data) |a_byte, b_byte| {
            if (a_byte > b_byte) break .gt;
            if (a_byte < b_byte) break .lt;
        } else .eq;
    }

    pub fn parseBase58String(str: []const u8) error{InvalidHash}!Hash {
        if (str.len > BASE58_MAX_SIZE) return error.InvalidHash;
        var encoded: std.BoundedArray(u8, BASE58_MAX_SIZE) = .{};
        encoded.appendSliceAssumeCapacity(str);

        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        const decoded = BASE58_ENDEC.decodeBounded(BASE58_MAX_SIZE, encoded) catch {
            return error.InvalidHash;
        };

        if (decoded.len != SIZE) return error.InvalidHash;
        return .{ .data = decoded.constSlice()[0..SIZE].* };
    }

    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);
    pub const Base58String = std.BoundedArray(u8, BASE58_MAX_SIZE);
    pub fn base58String(self: Hash) Base58String {
        return BASE58_ENDEC.encodeArray(SIZE, self.data);
    }

    pub fn format(
        self: Hash,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        const str = self.base58String();
        return writer.writeAll(str.constSlice());
    }

    /// Intended to be used in tests.
    pub fn initRandom(random: std.Random) Hash {
        var data: [SIZE]u8 = undefined;
        random.bytes(&data);
        return .{ .data = data };
    }
};
