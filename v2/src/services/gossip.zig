//! This service listens on a ringbuffer of packets, communicating with other solana gossip nodes to
//! share and broadcast validator contact information and events
//! (votes, duplicate_shred, fork restarts, snapshot hashes)

const std = @import("std");
const start = @import("start");
const common = @import("common");
const tracy = @import("tracy");

const Pair = common.net.Pair;
const Packet = common.net.Packet;
const Pubkey = common.solana.Slot;
const Slot = common.solana.Slot;
const Hash = common.solana.Hash;

comptime {
    _ = start;
}

pub const name = .gossip;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    pair: *Pair,
    snapshot_queue: *common.gossip.SnapshotContactQueue,
};

pub const ReadOnly = struct {
    config: *const common.gossip.GossipConfig,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    std.log.debug("Gossip starting on {f}:{}", .{ ro.config.keypair.pubkey, rw.pair.port });

    while (true) {
        std.atomic.spinLoopHint();
    }
}

// const Timestamp = u64;

// fn TimerHeap(comptime Value: type) type {
//     return struct {
//         array: std.ArrayListUnmanaged(Entry),

//         const Self = @This();
//         const Entry = struct { timestamp: Timestamp, value: Value };

//         pub fn initCapacity(allocator: std.mem.Allocator, capacity: usize) !Self {
//             var array: std.ArrayListUnmanaged(Entry) = .empty;
//             try array.ensureTotalCapacity(allocator, capacity);
//             return .{ .array = array };
//         }

//         pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
//             var array = self.array;
//             array.deinit(allocator);
//         }

//         pub fn insert(self: *Self, timestamp: Timestamp) *Value {
//             const entry = self.array.addOneAssumeCapacity();
//             entry.timestamp = timestamp;

//             // siftUp
//             var i = self.array.items.len - 1;
//             while (i > 0) {
//                 const parent = (i - 1) / 2;
//                 if (self.array.items[parent].timestamp <= self.array.items[i].timestamp) break;
//                 std.mem.swap(Entry, &self.array.items[parent], &self.array.items[i]);
//                 i = parent;
//             }
//         }

//         pub fn peekOldest(self: *const Self) ?struct{ Timestamp, *Value } {
//             if (self.array.items.len == 0) return null;
//             const min_entry = &self.array.items[0];
//             return .{ min_entry.timestamp, &min_entry.value };
//         }

//         pub fn updateOldest(self: *Self, op: union(enum) { modified: Timestamp, removed }) void {
//             switch (op) {
//                 .modified => |ts| self.array.items[0].timestamp = ts,
//                 .removed => _ = self.array.swapRemove(0),
//             }

//             // siftDown
//             var i: usize = 0;
//             while (true) {
//                 var smallest = i;
//                 for ([_]bool{ true, false }) |is_right| {
//                     const child = (i * 2) + @intFromBool(is_right);
//                     if (child < self.array.items.len and
//                         self.array.items[child].timestamp < self.array.items[i].timestamp)
//                     {
//                         smallest = child;
//                     }
//                 }
//                 if (smallest == i) break;
//                 std.mem.swap(Entry, &self.array.items[i], &self.array.items[smallest]);
//                 i = smallest;
//             }
//         }
//     };
// }

// const GossipKey = struct {
//     from: Pubkey,
//     tag: enum(u8) {
//         vote,
//         lowest_slot,
//         epoch_slots,
//         duplicate_shred,
//         snapshot_hashes,
//         contact_info,
//         restart_last_fork,
//         restart_heaviest_fork,
//     },
//     tag_idx: u16,
// };

// const GossipTable = struct {
//     map: std.AutoArrayHashMapUnmanaged(GossipKey, Value),
//     timer: TimerHeap(GossipKey),

//     const Value = struct {
//         duplicates: u8,
//         hash: Hash,
//         wallclock: Timestamp,
//         value: struct {
//             len: u16,
//             bytes: [Packet.len]u8,
//         },
//     };

//     pub fn insert(
//         self: *GossipTable,
//         key_ptr: *const GossipKey,
//         wallclock: Timestamp,
//         value: []const u8,
//     ) u8 {
//         if (self.map.count() == self.map.capacity()) {

//         }
//     }
// };

// const GossipPeers = struct {};
