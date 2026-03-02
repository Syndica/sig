const std = @import("std");
const Ring = @import("ring.zig").Ring;
const common = @import("../common.zig");

const Atomic = std.atomic.Value;

const Pubkey = common.solana.Pubkey;
const Signature = common.solana.Signature;
const Slot = common.solana.Slot;
const Hash = common.solana.Hash;

/// A wrapper around stdlib's Keypair so that it:
/// 1. supports cross-process (shared memory) serialization
/// 2. easily compatible with our Signature and Pubkey types
pub const KeyPair = extern struct {
    pubkey: Pubkey,
    secret: [64]u8,

    pub fn fromKeyPair(kp: std.crypto.sign.Ed25519.KeyPair) KeyPair {
        return .{
            .pubkey = .fromPublicKey(&kp.public_key),
            .secret = kp.secret_key.bytes,
        };
    }

    pub inline fn generateDeterminisic(seed: [32]u8) KeyPair {
        return fromKeyPair(.generateDeterministic(seed));
    }

    pub inline fn generate() KeyPair {
        return fromKeyPair(.generate());
    }

    pub fn sign(self: *const KeyPair, msg: []const u8) !Signature {
        const kp: std.crypto.sign.Ed25519.KeyPair = .{
            .public_key = try .fromBytes(self.pubkey.data),
            .secret_key = try .fromBytes(self.secret),
        };
        return .fromSignature(try kp.sign(msg, null));
    }
};

/// A signable message using SPSC communication
pub fn Signer(comptime max_message_size: usize) type {
    return extern struct {
        incoming: [max_message_size]u8,
        signature: Signature,
        state: Atomic(State),

        const Self = @This();
        const State = packed struct(u32) {
            // extra states to track misuse: probably isn't needed.
            mode: enum(u3){ idle, writing, written, signing, signed },
            bytes: u29 = 0,
        };

        pub fn init(self: *Self) void {
            self.state = .init(.{ .mode = .idle });
        }

        pub fn getWriter(self: *Self) std.Io.Writer {
            // idle -> writing (no ordering needed)
            std.debug.assert(self.state.swap(.{ .mode = .writing }, .monotonic).mode == .idle);
            return .fixed(&self.incoming);
        }

        pub fn signWritten(self: *Self, writer: *const std.Io.Writer) Signature {
            const slice = writer.buffered();
            std.debug.assert(slice.ptr == self.incoming[0..].ptr);
            std.debug.assert(slice.len <= self.incoming.len);

            // writing -> written (Release: self.incoming writes happens-before this)
            const write_state: State = .{ .mode = .written, .bytes = @intCast(slice.len) };
            std.debug.assert(self.state.swap(write_state, .release).mode == .writing);

            // wait for written -> signed (Acquire: self.signature write happens-before this)
            while (true) : (std.atomic.spinLoopHint()) {
                const s = self.state.load(.acquire);
                switch (s.mode) {
                    .idle, .writing => unreachable,
                    .written, .signing => continue,
                    .signed => {
                        const signature = self.signature;

                        // signed -> idle (no ordering needed)
                        const old_state = self.state.swap(.{ .mode = .idle }, .monotonic);
                        std.debug.assert(old_state.mode == .signed);
                        return signature;
                    },
                }
            }
        }

        pub fn tryCompleteSignature(self: *Self, keypair: *const KeyPair) !?usize {
            // wait until written
            if (self.state.load(.monotonic).mode != .written) {
                return null;
            }

            // written -> signing (Acquire: self.incoming writes happens-before this)
            const old_state = self.state.swap(.{ .mode = .signing }, .acquire);
            std.debug.assert(old_state.mode == .written);
            std.debug.assert(old_state.bytes > 0);
            std.debug.assert(old_state.bytes <= self.incoming.len);

            const n = old_state.bytes;
            self.signature = try keypair.sign(self.incoming[0..n]);

            // signing -> signed (Release: self.signature write happens-before this)
            std.debug.assert(self.state.swap(.{ .mode = .signed }, .release).mode == .signing);
            return n;
        }
    };
}
