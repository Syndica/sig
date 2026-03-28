const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");

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
    const zone = tracy.Zone.init(@src(), .{ .name = @tagName(name) });
    defer zone.deinit();

    var fba = std.heap.FixedBufferAllocator.init(&scratch_memory);
    const allocator = fba.allocator();

    var state: State = try .init(allocator);

    while (true) {
        var read = rw.deshredded_in.getReadable() catch continue;

        const deshredded_fec_set: *const lib.shred.DeshreddedFecSet = read.get(0);
        defer read.markUsed(1);

        const received_zone = tracy.Zone.init(@src(), .{ .name = "received fec set" });
        defer received_zone.deinit();

        const entry = state.insertGetChained(deshredded_fec_set);

        std.log.info(
            "finished fec set {} {f}, insert: {s}",
            .{ deshredded_fec_set.id, deshredded_fec_set.merkle_root, @tagName(entry) },
        );
    }
}

const State = struct {
    map: MerkleRootMap,

    fn init(allocator: std.mem.Allocator) !State {
        var root_map: MerkleRootMap = .empty;
        errdefer root_map.deinit(allocator);
        try root_map.ensureTotalCapacity(allocator, 1024);

        return .{
            .map = root_map,
        };
    }

    const InsertResult = union(enum) {
        already_known,
        inserted,
        inserted_known_chain: MerkleRootMap.Entry,
    };

    fn insertGetChained(self: *State, deshredded: *const lib.shred.DeshreddedFecSet) InsertResult {
        // TODO: eviction

        _ = self;
        _ = deshredded;
        return .inserted;

        // const get_or_put = self.map.getOrPutAssumeCapacity(deshredded.merkle_root);
        // if (get_or_put.found_existing) return .already_known;
        // get_or_put.value_ptr.* = .init(deshredded);

        // const chained = self.map.getEntry(deshredded.chained_merkle_root) orelse
        //     return .inserted;

        // get_or_put.value_ptr.prev = chained.value_ptr;

        // if (deshredded.slot_complete) {
        //     var maybe_node = get_or_put.value_ptr.prev;
        //     while (maybe_node) |node| : (maybe_node = node.prev) {
        //         if (node.id.fec_set_idx == 0)
        //             std.log.info("Finished chain! {}->{}", .{ node.id, deshredded.id });
        //     }
        // }

        // return .{ .inserted_known_chain = chained };
    }

    const MerkleRootMap = std.ArrayHashMapUnmanaged(void, *Value, Context, true);

    const Context = struct {
        pub fn hash(ctx: Context, key: Hash) u32 {
            _ = ctx;
            return @bitCast(key.data[0..4].*);
        }
        pub fn eql(ctx: Context, a: Hash, b: Hash, key_idx: usize) bool {
            _ = ctx;
            _ = key_idx;
            return a.eql(&b);
        }
    };

    const Value = extern struct {
        chained_merkle_root: Hash,
        id: FecSetId,
        data_complete: bool,
        slot_complete: bool,
        payload_len: u16,

        // the node found by the chained merkle root
        // NOTE: we can't use a normal next pointer
        prev: ?*Value = null,

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

const MapTreeNode = extern struct {
    parent: PoolIdx = .null,
    child: PoolIdx = .null,
    sibling: PoolIdx = .null,

    merkle_root: Hash,
    chained_merkle_root: Hash,
    id: FecSetId,
    data_complete: bool,
    slot_complete: bool,
    payload_len: u16,

    // TODO: this shouldn't be copied, and should instead come in via a pool
    payload_buf: [32 * Shred.data_payload_max]u8,

    pub fn format(node: *const MapTreeNode, writer: *std.io.Writer) !void {
        try writer.print(
            \\ {{
            \\     id: {}, 
            \\     parent: {}, child: {}, sibling: {}
            \\     root: {f}, chained_root: {f}
            \\     data_complete: {}, slot_complete: {}
            \\ }}
            \\
        , .{
            node.id,
            node.parent,
            node.child,
            node.sibling,
            node.merkle_root,
            node.chained_merkle_root,
            node.data_complete,
            node.slot_complete,
        });
    }
};

const MapTree = struct {
    pool: NodePool,
    tree: NodeTree,
    map: Map, // merkle-hash -> node
    const capacity = 128;

    const Map = std.ArrayHashMapUnmanaged(void, *MapTreeNode, Context, true);
    const NodePool = Pool(MapTreeNode, capacity);
    const NodeTree = Tree(MapTreeNode, capacity);

    const Context = struct {
        map: *const Map,

        pub fn hash(ctx: Context, key: *const Hash) u32 {
            _ = ctx;
            return @bitCast(key.data[0..4].*);
        }
        pub fn eql(ctx: Context, a: *const Hash, _: void, key_idx: usize) bool {
            const b: *const Hash = &ctx.map.values()[key_idx].merkle_root;
            return a.eql(b);
        }
    };

    fn init(self: *MapTree, allocator: std.mem.Allocator) !void {
        self.pool = .init();
        self.tree = .{ .buf = @ptrCast(&self.pool.buf) };
        self.map = .empty;
        try self.map.ensureTotalCapacity(allocator, capacity);
    }

    const InsertResult = union(enum) {
        already_known,
        inserted,
        inserted_known_chain: *MapTreeNode,

        pub fn format(self: InsertResult, writer: *std.io.Writer) !void {
            switch (self) {
                .already_known, .inserted => try writer.print("{s}", .{@tagName(self)}),
                .inserted_known_chain => |node| try writer.print("{s}: {f}", .{ @tagName(self), node }),
            }
        }
    };

    fn put(self: *MapTree, new_fec_set: *const lib.shred.DeshreddedFecSet) !InsertResult {
        const ctx: Context = .{ .map = &self.map };

        const result = self.map.getOrPutAssumeCapacityAdapted(&new_fec_set.merkle_root, ctx);
        if (result.found_existing) return .already_known;

        const node = try self.pool.create();
        result.value_ptr.* = node;

        node.* = .{
            .merkle_root = new_fec_set.merkle_root,
            .chained_merkle_root = new_fec_set.chained_merkle_root,
            .id = new_fec_set.id,
            .data_complete = new_fec_set.data_complete,
            .slot_complete = new_fec_set.slot_complete,
            .payload_len = new_fec_set.payload_len,
            .payload_buf = new_fec_set.payload_buf,
        };

        if (self.map.getAdapted(&new_fec_set.chained_merkle_root, ctx)) |parent| {
            self.tree.insert(parent, node);
            return .{ .inserted_known_chain = parent };
        }
        return .inserted;

        // self.tree.insert();

        // return (self.map.getEntryAdapted(merkle_root, Context{ .map = &self.map }) orelse return null).value_ptr.*;
    }
};

test MapTree {
    var tree: MapTree = undefined;
    try tree.init(std.testing.allocator);
    defer tree.map.deinit(std.testing.allocator);

    const a_hash: Hash = .parse("ByzshhkRgXWnTkHjapkkqaKgEFnsg8ceY3bw4MWBzFE");
    const b_hash: Hash = .parse("BMHr4knWhDp8JhqCYhA2K5DUYQsYUVXdy2zWahzt5jLd");
    const c_hash: Hash = .parse("2GyMeUytf6fcsfNP2QQ6F5e5qwAUoMtKUbnH6QU6bTNm");

    const a: lib.shred.DeshreddedFecSet = .{
        .chained_merkle_root = .parse("DWCWjQciWoWDzJKwqUZ1ntKqTyXtLVt4C8aL7biBJZ4z"), // prev slot
        .merkle_root = a_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 0 },

        .data_complete = true,
        .slot_complete = false,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    const b: lib.shred.DeshreddedFecSet = .{
        .chained_merkle_root = a_hash,
        .merkle_root = b_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 0 },

        .data_complete = true,
        .slot_complete = false,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    const c: lib.shred.DeshreddedFecSet = .{
        .chained_merkle_root = b_hash,
        .merkle_root = c_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 0 },

        .data_complete = true,
        .slot_complete = true,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    std.debug.print("{f}\n", .{try tree.put(&a)});
    std.debug.print("{f}\n", .{try tree.put(&b)});
    std.debug.print("{f}\n", .{try tree.put(&c)});
}

fn Tree(
    Node: type,
    comptime capacity: usize,
    // comptime parent_field: []const u8,
    // comptime child_field: []const u8,
    // comptime sibling_field: []const u8,
) type {
    const needed_fields: []const []const u8 = &.{ "parent", "child", "sibling" };

    for (needed_fields) |field| {
        if (!@hasField(Node, field)) {
            @compileLog("missing field", Node, field);
            continue;
        }
        if (@TypeOf(@field(@as(Node, undefined), field)) != PoolIdx) @compileLog("incorrect type", Node, field);
    }

    return extern struct {
        buf: *[capacity]Node,

        const Self = @This();

        fn ptrToIdx(self: *const Self, node: *Node) PoolIdx {
            const idx = @as([*]Node, node[0..1]) - self.buf.ptr;
            return @enumFromInt(idx);
        }

        fn insert(self: *const Self, parent: *Node, new_node: *Node) void {
            std.debug.assert(new_node.parent == .null);
            std.debug.assert(new_node.child == .null);
            std.debug.assert(new_node.sibling == .null);

            new_node.parent = self.ptrToIdx(parent);

            if (parent.child == .null) {
                parent.child = self.ptrToIdx(new_node);
            } else {
                new_node.sibling = parent.child;
                parent.child = self.ptrToIdx(new_node);
            }
        }
    };
}

const PoolIdx = enum(usize) {
    null = std.math.maxInt(usize),
    _,
};

fn Pool(Item: type, comptime capacity: usize) type {
    std.debug.assert(capacity < std.math.maxInt(usize));

    return extern struct {
        free_list: Idx,
        buf: [capacity]Node,

        // We know when next_free is active when we walk the free_list
        const Node = extern union { next_free: Idx, item: Item };
        const Idx = PoolIdx;

        comptime {
            if (@sizeOf(Item) < @sizeOf(Idx)) unreachable;
            if (@alignOf(Item) < @alignOf(Idx)) unreachable;

            if (@sizeOf(Node) != @sizeOf(Item)) unreachable;
            if (@alignOf(Node) != @alignOf(Item)) unreachable;
        }

        // alignOf(Node) >= alignOf(Item)
        const ItemPtr = *align(@alignOf(Node)) Item;

        const Self = @This();

        fn init() Self {
            // place all nodes in the free list
            // (0) -> (1) -> ... ->(buf.len - 1) -> (null)
            var buf: [capacity]Node = undefined;
            for (buf[0 .. buf.len - 1], 0..) |*node, i| {
                node.* = .{ .next_free = @enumFromInt(i + 1) };
            }
            buf[buf.len - 1] = .{ .next_free = .null };

            return .{ .buf = buf, .free_list = @enumFromInt(0) };
        }

        // take head off free_list
        fn create(self: *Self) !ItemPtr {
            if (self.free_list == .null) return error.OutOfSpace;

            const idx = self.free_list;
            self.free_list = self.buf[@intFromEnum(self.free_list)].next_free;

            return @ptrCast(&self.buf[@intFromEnum(idx)]);
        }

        // place item as head of free_list
        fn destroy(self: *Self, item: ItemPtr) void {
            item.* = undefined;

            const node: *Node = @ptrCast(item);
            node.* = .{ .next_free = self.free_list };
            self.free_list = self.ptrToIndex(item);
        }

        fn ptrToIndex(self: *const Self, item: ItemPtr) Idx {
            const node: [*]const Node = @ptrCast(item);
            const base: [*]const Node = &self.buf;
            return @enumFromInt(node - base);
        }
    };
}

test "pool create + destroy" {
    const capacity = 1024;

    var pool: Pool(i64, capacity) = .init();

    for (0..capacity + 1) |i| {
        if (i == capacity) {
            try std.testing.expectError(error.OutOfSpace, pool.create());
            continue;
        }

        const x: *i64 = try pool.create();
        x.* = -(@as(i64, @intCast(i)) * 2);
    }

    for (0..capacity) |i| {
        const node = &pool.buf[i];
        const x: *i64 = @ptrCast(node);
        std.debug.assert(x.* == -(@as(i64, @intCast(i)) * 2));
        pool.destroy(@ptrCast(&pool.buf[i]));
    }

    for (0..capacity + 1) |i| {
        if (i == capacity) {
            try std.testing.expectError(error.OutOfSpace, pool.create());
            continue;
        }

        const x: *i64 = try pool.create();
        x.* = -(@as(i64, @intCast(i)) * 2);
    }
}

test "pool create + destroy out of order" {
    var pool: Pool(i64, 3) = .init();

    const a = try pool.create();
    const b = try pool.create();
    const c = try pool.create();

    a.* = 0;
    b.* = 10;
    c.* = 30;

    pool.destroy(b);
    pool.destroy(a);

    const x = try pool.create();
    const y = try pool.create();

    try std.testing.expectEqual(a, x);
    try std.testing.expectEqual(b, y);
}

// const MerkleForest = struct {
//     /// Hash -> Node lookups
//     map: State.MerkleRootMap,

//     const MerkleRootMap = std.ArrayHashMapUnmanaged(Hash, Value, Context, true);

//     const Node
// };

// std.heap.MemoryPool(comptime Item: type)

// std.heap.MemoryPool(comptime Item: type)

// fn ParentChildSiblingTree(Value: type, IntIndex: type) type {
//     // if (@typeInfo(Value) != .pointer) @compileError("Value expected to be pointer");

//     return extern struct {
//         nodes: []Node,

//         const Self = @This();

//         const null_int_index = std.math.maxInt(IntIndex);

//         const Idx = enum(IntIndex) { null = null_int_index };

//         const Node = extern struct {
//             parent: IntIndex,
//             child: IntIndex,
//             sibling: IntIndex,
//             value: Value,
//         };

//         fn init(allocator: std.mem.Allocator, max_node_count: IntIndex) !Self {
//             const max_idx = max_node_count - 1;
//             std.debug.assert(max_idx < null_int_index); // must leave room for the null index
//             return .{
//                 .nodes = try allocator.alloc(Node, max_node_count),
//             };
//         }

//         // fn insert(parent: *Value)
//     };
// }
