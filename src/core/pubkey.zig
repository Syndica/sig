const std = @import("std");
const base58 = @import("base58");

const encoder = base58.Encoder.init(.{});
const decoder = base58.Decoder.init(.{});

pub const Pubkey = struct {
    data: [32]u8,
    cached_str: ?[44]u8,

    const Self = @This();

    /// ***fromString*** takea a base58 encoded string and decodes the value. It also caches
    /// the `str` for future calls to string() method.
    /// If `bytes`, it wil automatically encode so that it's able to call string() method.
    ///
    pub fn fromString(str: []const u8) !Self {
        if (str.len != 44) {
            return Error.InvalidEncodedLength;
        }
        var out: [32]u8 = .{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };
        var written = decoder.decode(str, &out) catch return Error.InvalidEncodedValue;
        if (written != 32) {
            @panic("written is not 32");
        }
        return Self{ .data = out, .cached_str = str[0..44].* };
    }

    /// ***fromBytes*** will automatically base58 decode the value. It will also cache the decoded string
    /// for future calls to string() method.
    ///
    /// Options:
    /// - `skip_encoding`: If (in the unlikely scenario) you will never call the string() method, you can
    /// set this option to true and it will not decode & cache the encoded value. This can be helpful in
    /// scenarios where you plan to only use the bytes and want to save on expensive base58 encoding. This is
    /// only valid if `bytes` union was passed to ***from***.
    ///
    pub fn fromBytes(bytes: []const u8, opts: struct { skip_encoding: bool = false }) !Self {
        if (bytes.len != 32) {
            return Error.InvalidBytesLength;
        }
        if (opts.skip_encoding) {
            return Self{ .data = bytes[0..32].*, .cached_str = null };
        }
        var dest: [44]u8 = .{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };

        var written = encoder.encode(bytes, &dest) catch @panic("could not encode pubkey");
        if (written != 44) {
            @panic("written is not 44");
        }
        return Self{ .data = bytes[0..32].*, .cached_str = dest[0..44].* };
    }

    pub fn string(self: *const Self) []const u8 {
        if (self.cached_str) |_| {
            return &self.cached_str.?[0..].*;
        }
        @panic("call to Pubkey.string() after opt `skip_encoding` asserted");
    }
};

const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
