const std = @import("std");
const start = @import("start");
const lib = @import("lib");

const Packet = lib.net.Packet;
const Hash = lib.solana.Hash;

const Shred = lib.shred.Shred;
const FecSetId = lib.shred.FecSetId;

comptime {
    _ = start;
}

pub const name = .replay;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    deshredded_in: *lib.shred.DeshredRing,
};

var scratch_memory: [256 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(rw: ReadWrite) !noreturn {
    var fba = std.heap.FixedBufferAllocator.init(&scratch_memory);
    const allocator = fba.allocator();

    var state: State = try .init(allocator);

    while (true) {
        var read = rw.deshredded_in.getReadable() catch continue;

        const deshredded_fec_set: *const lib.shred.DeshreddedFecSet = read.get(0);
        defer read.markUsed(1);

        std.log.info(
            "finished fec set {} {f}",
            .{ deshredded_fec_set.id, deshredded_fec_set.merkle_root },
        );
    }
}

const State = struct {
    map: MerkleRootMap,

    fn init(allocator: std.mem.Allocator) !State {
        var root_map: MerkleRootMap = .empty;
        errdefer root_map.deinit(allocator);
        root_map.ensureTotalCapacity(allocator, 1024);

        return .{
            .map = root_map,
        };
    }

    fn insert(self: *State, deshredded: *const lib.shred.DeshreddedFecSet) !void {
        // TODO: eviction

        const get_or_put = self.map.getOrPutAssumeCapacity(deshredded.merkle_root);
        if (get_or_put.found_existing) return;
        get_or_put.value_ptr.* = .init(deshredded);
    }

    const MerkleRootMap = std.ArrayHashMapUnmanaged(Hash, Value, Context, true);

    const Context = struct {
        pub fn hash(ctx: Context, key: Hash) u32 {
            _ = ctx;
            return key.bytes()[0..4].*;
        }
        pub fn eql(ctx: Context, a: Hash, b: Hash, key_idx: usize) bool {
            _ = ctx;
            _ = key_idx;
            return a.eql(b);
        }
    };

    const Value = extern struct {
        chained_merkle_root: Hash,
        id: FecSetId,
        data_complete: bool,
        slot_complete: bool,
        payload_len: u16,

        // TODO: this shouldn't be copied, and should instead come in via a pool
        payload_buf: [32 * Shred.data_payload_max]u8,

        fn payload(self: *const Value) []const u8 {
            return self.payload_buf[0..self.payload_len];
        }

        fn init(deshredded: *const lib.shred.DeshreddedFecSet) Value {
            return .{
                .chained_merkle_root = deshredded.chained_merkle_root,
                .id = deshredded.id,
                .data_complete = deshredded.data_complete,
                .slot_complete = deshredded.slot_complete,
                .payload_len = deshredded.payload_len,
                .payload_buf = deshredded.payload_buf,
            };
        }
    };
};
