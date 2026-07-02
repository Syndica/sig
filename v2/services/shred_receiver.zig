//! Incoming UDP packets (typically port 8002) are sent in by the net service, via
//! `ReadWrite.tvu_socket`. This port is currently set by config.shred_network.recv_port.
//!
//! Shred receiver takes in these packets and emits completed FEC (Forward Error Correction) sets.
//! Each FEC set contains up to 32 packets (AKA shreds) worth of data, which are always sent out as
//! 32 code and 32 data shreds.
//!
//! A FEC set may be reconstructed once any of these 32/64 shreds have been received. This
//! reconstructed data encodes portions of (or whole) Entry batches.
//!
//! These Entry batches are produced by the leader, with each Entry batch forming a portion of the
//! block being produced. This is the data that feeds into Replay.
//!
//!
//!
//! This service has the following responsibilities:
//! 1) Checking that incoming packets are valid shreds, making sure that shreds:
//!     - Are the correct size
//!     - Have valid headers, and have a valid layout
//!     - Are properly signed by the leader for their respective slot
//!     - Have the same merkle root and signature as others in their FEC set
//!     - etc
//! 2) Grouping them into FEC sets
//! 3) Upon receiving enough shreds to complete a FEC set, using Reed-Solomon to reconstruct the
//!    data from said FEC set
//! 4) Sending the reconstructed data onwards
//!
//!
//! NOTE: This currently does not implement repair. Repair requests when implemented should bypass
//!       early equivocation checks.
//!
//! NOTE: This service stores at most one instance of each FecSetId (slot + fecset index).
//!
//!       This means that incoming shreds with the same FecSetId which cannot fit into the currently
//!       in-progress FEC set due to a mismatch (i.e. when the Signature or Merkle root are
//!       different) are dropped under equivocation.
//!
//!       For example, if the shreds of two mismatching FEC sets of the same FecSetId came in
//!       interleaved we would drop the 2nd FEC set. In this case we may have to get shreds from
//!       the missing set from repair. I expect this to be rare, and this behaviour matches
//!       Firedancer's.
//!
//!       Once we complete a FEC set, we are free to build another FEC set of that very same
//!       FecSetId; the downstream service must be fully aware of equivocation.
//!
//!       Once repair is implemented, shreds from it should bypass these checks and enter the map,
//!       even if there is already an instance of that FecSetId.
//!

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");

comptime {
    _ = start;
}

pub const name = .shred_receiver;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    /// Translation Validation Unit (TVU)'s UDP socket, i.e. where we receive shreds. This is
    /// typically port 8002. While we've obtained a net Pair, we only currently receive on this.
    /// I believe once we support retransmit, we will be sending on it too.
    tvu_socket: *lib.net.Pair,

    /// Where we send our deshredded FEC (Forward Error Correction) sets to be assembled for replay.
    /// FEC sets will be sent out as they complete.
    ///
    /// NOTE: it will be more performant in future to only send headers down the ring buffer, and
    /// write to a shared fec-set pool.
    deshredded_out: *lib.shred.DeshredRing,

    tel: *lib.telemetry.Region,
};

pub const ReadOnly = struct {
    config: *const lib.shred.RecvConfig,
};

var scratch_memory: [1024 * 1024 * 1024]u8 = undefined;
const max_in_progress = 8192;
const max_done = 65536;

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    const zone = tracy.Zone.init(@src(), .{ .name = @tagName(name) });
    defer zone.deinit();

    var fba: std.heap.FixedBufferAllocator = .init(&scratch_memory);
    const allocator = fba.allocator();

    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();
    logger.info().logf("Waiting for shreds on port {}", .{rw.tvu_socket.port});

    var packet_iter = rw.tvu_socket.recv.get(.reader);
    var deshred_out = rw.deshredded_out.get(.writer);

    const Effects = struct {
        deshred_writer: *lib.shred.DeshredRing.Iterator(.writer),

        const Self = @This();

        /// NOTE: Pointers passed to this hook are only valid for the duration of this callback.
        pub fn reportFecSetCompleted(
            self: Self,
            completed: *const lib.shred.DeshreddedFecSet,
            ctx: *const lib.shred.FecSetCtx,
        ) void {
            _ = .{ self, completed, ctx };
        }

        pub fn writeCompletedFecSet(self: Self) *lib.shred.DeshreddedFecSet {
            return self.deshred_writer.next() orelse
                // If there's nowhere to write to, then this means that services downstream haven't been
                // keeping up for a while.
                // For now let's just exit if this happens, however this might leave us vulnerable to denial
                // of service.
                //
                // TODO: consider handling this case by pausing writing to this ring.
                @panic("Can't send deshredded fec sets to replay, is it alive?");
        }

        pub fn flushCompletedFecSet(self: Self) void {
            self.deshred_writer.markUsed();
        }
    };

    const Receiver = lib.shred.Receiver(Effects);
    const effects: Effects = .{ .deshred_writer = &deshred_out };
    var receiver: Receiver = try .init(allocator, max_in_progress, max_done, effects);
    defer receiver.deinit(allocator);

    while (true) {
        {
            const idle_zone = tracy.Zone.init(@src(), .{ .name = "idle" });
            defer idle_zone.deinit();
            while (packet_iter.peek() == null) {
                try runner.activity.signalIdleSpinning();
            }
        }
        while (packet_iter.next()) |packet| {
            defer packet_iter.markUsed();
            try runner.activity.signalActive();

            const result = receiver.processPacket(
                &ro.config.leader_schedule,
                ro.config.shred_version,
                packet,
                logger.withScope("processPacket"),
            ) catch |err| switch (err) {
                error.NoSpaceLeft => return err,
                else => {
                    logger.warn().logf("packet failed with {}", .{err});
                    continue;
                },
            };
            _ = result;
        }
    }
}
