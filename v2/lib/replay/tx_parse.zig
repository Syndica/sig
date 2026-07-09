//! Zero-copy parsing of `VersionedTransaction` to extract static keys and ALTs without
//! requiring a stack buffer.
//! TODO: should this live elsewhere?

const std = @import("std");
const lib = @import("../lib.zig");

const Pubkey = lib.solana.Pubkey;
const Signature = lib.solana.Signature;

// Alignment and size assumptions.
comptime {
    std.debug.assert(@sizeOf(Pubkey) == 32);
    std.debug.assert(@alignOf(Pubkey) == 1);

    std.debug.assert(@sizeOf(Signature) == 64);
    std.debug.assert(@alignOf(Signature) == 1);
}

pub const ParseError = error{
    ShortBuffer,
    MalformedShortVec,
    UnsupportedVersion,
    Overflow,
};

pub const ParsedMessageAccounts = struct {
    static_keys: []const Pubkey,
    address_table_lookups: AddressLookupIter,
    is_v0: bool,

    pub fn hasAltLookups(self: ParsedMessageAccounts) bool {
        return self.address_table_lookups.len != 0;
    }
};

pub const AddressLookupView = struct {
    account_key: *const Pubkey,
    writable_indexes: []const u8,
    readonly_indexes: []const u8,
};

pub const AddressLookupIter = struct {
    bytes: []const u8 = &.{},
    len: usize = 0,
    index: usize = 0,

    pub fn next(self: *AddressLookupIter) ParseError!?AddressLookupView {
        if (self.index >= self.len) return null;
        self.index += 1;

        var c: Cursor = .{ .bytes = self.bytes };

        const account_key = try c.takeOne(Pubkey);
        const writable_indexes = try c.takeShortBytes();
        const readonly_indexes = try c.takeShortBytes();

        self.bytes = c.bytes[c.pos..];

        return .{
            .account_key = account_key,
            .writable_indexes = writable_indexes,
            .readonly_indexes = readonly_indexes,
        };
    }
};

const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: Cursor) usize {
        return self.bytes.len - self.pos;
    }

    fn readByte(self: *Cursor) ParseError!u8 {
        if (self.pos >= self.bytes.len) return error.ShortBuffer;
        defer self.pos += 1;
        return self.bytes[self.pos];
    }

    fn skip(self: *Cursor, n: usize) ParseError!void {
        if (n > self.remaining()) return error.ShortBuffer;
        self.pos += n;
    }

    fn takeBytes(self: *Cursor, n: usize) ParseError![]const u8 {
        if (n > self.remaining()) return error.ShortBuffer;
        const out = self.bytes[self.pos..][0..n];
        self.pos += n;
        return out;
    }

    fn takeOne(self: *Cursor, comptime T: type) ParseError!*const T {
        comptime std.debug.assert(@alignOf(T) == 1);

        const raw = try self.takeBytes(@sizeOf(T));
        return @ptrCast(raw.ptr);
    }

    fn takeSlice(self: *Cursor, comptime T: type, len: usize) ParseError![]const T {
        comptime std.debug.assert(@alignOf(T) == 1);

        const byte_len = std.math.mul(usize, len, @sizeOf(T)) catch return error.Overflow;
        const raw = try self.takeBytes(byte_len);

        return @as([*]const T, @ptrCast(raw.ptr))[0..len];
    }

    fn takeShortLen(self: *Cursor) ParseError!usize {
        // Strict Solana shortvec/u16-ish decoder.
        // This rejects infinite continuaion, overflow, and non-canonical
        // trailing-zero aliases.
        // TODO: citation needed.
        var value: u16 = 0;

        inline for (0..3) |nth_byte| {
            const b = try self.readByte();

            if (nth_byte != 0 and b == 0)
                return error.MalformedShortVec;

            const part: u16 = b & 0x7f;
            const done = (b & 0x80) == 0;

            if (nth_byte == 2 and !done)
                return error.MalformedShortVec;

            const shifted: u32 = @as(u32, part) << @intCast(nth_byte * 7);
            const new_value: u32 = @as(u32, value) | shifted;
            value = std.math.cast(u16, new_value) orelse return error.MalformedShortVec;

            if (done) return value;
        }

        return error.MalformedShortVec;
    }

    fn takeShortBytes(self: *Cursor) ParseError![]const u8 {
        const len = try self.takeShortLen();
        return self.takeBytes(len);
    }

    fn takeShortSlice(self: *Cursor, comptime T: type) ParseError![]const T {
        const len = try self.takeShortLen();
        return self.takeSlice(T, len);
    }

    fn skipShortBytes(self: *Cursor) ParseError!void {
        const len = try self.takeShortLen();
        try self.skip(len);
    }
};
