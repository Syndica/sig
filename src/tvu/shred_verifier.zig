const std = @import("std");
const sig = @import("../lib.zig");
const network = @import("zig-network");

const shred_layout = sig.tvu.shred_layout;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Atomic;

const Channel = sig.sync.Channel;
const Packet = sig.net.Packet;

pub fn runShredSigVerify(
    exit: *Atomic(bool),
    incoming: *Channel(ArrayList(Packet)),
    verified: *Channel(ArrayList(Packet)),
) void {
    while (incoming.receive()) |packet_batch| {
        // TODO parallelize this once it's actually verifying signatures
        for (packet_batch.items) |*packet| {
            if (!verifyShred(packet, {})) {
                packet.set(.discard);
            }
        }
        verified.send(packet_batch) catch unreachable; // TODO
        if (exit.load(.Monotonic)) return;
    }
}

/// verify_shred_cpu
/// TODO slot leaders
fn verifyShred(packet: *const Packet, slot_leaders: void) bool {
    if (packet.isSet(.discard)) return false;
    const shred = shred_layout.getShred(packet) orelse return false;
    const slot = shred_layout.getSlot(shred) orelse return false;
    const signature = shred_layout.getSignature(shred) orelse return false;
    const signed_data = shred_layout.getSignedData(shred) orelse return false;

    // TODO get slot leader pubkey and actually verify signature
    _ = slot_leaders;
    _ = slot;
    if (false) return signature.verify(unreachable, signed_data.data);

    return true;
}

// pub const EpochLeaderSchedule = struct {
//     data: []const sig.core.Pubkey,
//     first_slot: sig.core.Slot,

//     fn getLeader(self: *@This(), slot: sig.core.Slot) sig.core.Pubkey {
//         const index = @as(usize, @intCast(slot)) - @as(usize, @intCast(self.first_slot));
//         return self.data[index];
//     }
// };

fn runLoopService(
    config: LoopServiceConfig,
    job_to_loop: anytype,
    args: anytype,
) !void {
    config.logger.infof("starting {}", config.name);
    defer config.logger.infof("exiting {}", config.name);
    const timer = try std.time.Timer.start();
    var last_iteration = timer.lap();
    while (!config.exit.load(.Unordered)) {
        @call(.auto, job_to_loop, args) catch |e| {
            switch (config.error_handler) {
                .logger, .log_and_return => {
                    config.logger.errf("Unhandled error in {}: {}", .{ config.name, e });
                },
                else => {},
            }
            switch (config.error_handler) {
                .only_return, .log_and_return => return e,
                else => {},
            }
        };
        last_iteration = timer.lap();
        std.time.sleep(config.min_loop_duration_ns -| last_iteration);
    }
}

pub const LoopServiceConfig = struct {
    logger: sig.trace.Logger,
    exit: *Atomic(bool),
    min_loop_duration_ns: u64,
    name: []const u8,
    error_handler: enum {
        logger,
        log_and_return,
        only_return,
    } = .logger,

    function: fn () anyerror!void,
};

pub const LoopService = struct {
    function: fn () anyerror!void,

    fn init(function: anytype) LoopService {
        _ = function;
    }
};

fn generifun(function: anytype) fn (anytype) anyerror!void {
    return struct {
        fn genericVersion(args: anytype) anyerror!void {
            return @call(.auto, function, args);
        }
    }.genericVersion;
}
