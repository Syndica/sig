// Utils required for the runtime.
// Some of these utils are present elswhere in random places, for now to keep the pr review simple
// they are redefined here. This will be addressed in a follow up pr.
// TODO: move to external module

const std = @import("std");

/// Hashes the provided byte slices using SHA-256.
pub fn hashv(vals: []const []const u8) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (vals) |val| hasher.update(val);
    return hasher.finalResult();
}
