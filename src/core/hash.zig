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

    pub fn equals(a: SlotAndHash, b: SlotAndHash) bool {
        return order(a, b) == .eq;
    }
};

pub const Hash = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;

    pub const ZEROES: Hash = .{ .data = .{0} ** SIZE };

    /// Hashes the input byte slice(s) using SHA 256.
    ///
    /// If the passed-in type contains multiple byte slices, it will
    /// iterate/recurse over them in order, updating the hasher for all of them
    /// before finalizing at the end.
    pub fn generateSha256(
        /// May be a slice or array of bytes, or a slice, array, or tuple
        /// containing slices or arrays of bytes nested with arbitrary depth.
        ///
        /// for example:
        /// - []const u8
        /// - []const []const u8
        /// - [2]u8
        /// - *[13]u8
        /// - struct { [128]u8, []const []const u8, struct { []const u8 }, ... }
        data: anytype,
    ) Hash {
        var hasher = Sha256.init(.{});
        update(&hasher, data);
        return .{ .data = hasher.finalResult() };
    }

    /// re-hashes the current hash with the mixed-in byte slice(s).
    pub fn extendAndHash(self: Hash, data: anytype) Hash {
        return generateSha256(.{ self.data, data });
    }

    fn update(hasher: *Sha256, data: anytype) void {
        const T = @TypeOf(data);

        if (@typeInfo(T) == .@"struct") {
            inline for (data) |val| update(hasher, val);
        } else if (std.meta.Elem(T) == u8) switch (@typeInfo(T)) {
            .array => hasher.update(&data),
            else => hasher.update(data),
        } else {
            for (data) |val| update(hasher, val);
        }
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

    pub fn bytes(self: *Hash) []u8 {
        return &self.data;
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

// TODO add tests
/// A 16-bit, 1024 element lattice-based incremental hash based on blake3
pub const LtHash = struct {
    data: @Vector(1024, u16),

    pub const IDENTITY = LtHash{ .data = @splat(0) };

    pub const NUM_ELEMENTS: usize = 1024;

    pub fn bytes(self: *LtHash) []u8 {
        // TODO verify this is correct
        return @as([*]u8, @ptrCast(&self.data))[0..2048];
    }

    /// Mixes `other` into `self`
    ///
    /// This can be thought of as akin to 'insert'
    pub fn mixIn(self: *LtHash, other: *const LtHash) void {
        self.data +%= other.data;
    }

    /// Mixes `other` out of `self`
    ///
    /// This can be thought of as akin to 'remove'
    pub fn mixOut(self: *LtHash, other: *const LtHash) void {
        self.data -%= other.data;
    }
};
