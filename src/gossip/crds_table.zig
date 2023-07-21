const std = @import("std");
const AutoArrayHashMap = std.AutoArrayHashMap;

const bincode = @import("bincode-zig");

const Hash = @import("../core/hash.zig").Hash;
const SocketAddr = @import("net.zig").SocketAddr;

const crds = @import("./crds.zig");
const CrdsValue = crds.CrdsValue;
const CrdsData = crds.CrdsData;
const CrdsVersionedValue = crds.CrdsVersionedValue;
const CrdsValueLabel = crds.CrdsValueLabel;
const LegacyContactInfo = crds.LegacyContactInfo;

const Pubkey = @import("../core/pubkey.zig").Pubkey;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

// tmp upperbound on number for `get_nodes`
const MAX_N_NODES = 100;

/// Cluster Replicated Data Store
pub const CrdsTable = struct {
    store: AutoArrayHashMap(CrdsValueLabel, CrdsVersionedValue),
    nodes: AutoArrayHashMap(usize, void), // hashset

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .store = AutoArrayHashMap(CrdsValueLabel, CrdsVersionedValue).init(allocator),
            .nodes = AutoArrayHashMap(usize, void).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.store.deinit();
        self.nodes.deinit();
    }

    pub fn insert(self: *Self, value: CrdsValue, now: u64) !void {
        // TODO: check to make sure this sizing is correct or use heap
        var buf = [_]u8{0} ** 1024;
        var bytes = try bincode.writeToSlice(&buf, value, bincode.Params.standard);
        const value_hash = Hash.generateSha256Hash(bytes);
        const versioned_value = CrdsVersionedValue{
            .value = value,
            .value_hash = value_hash,
            .local_timestamp = now,
            .num_push_dups = 0,
        };

        const label = value.label();
        var result = try self.store.getOrPut(label);
        if (!result.found_existing) {
            switch (value.data) {
                .LegacyContactInfo => {
                    try self.nodes.put(result.index, {});
                },
                else => {},
            }

            result.value_ptr.* = versioned_value;
        } else {}
    }

    pub fn get_nodes(self: *Self) ![]*CrdsVersionedValue {
        var entry_ptrs: [MAX_N_NODES]*CrdsVersionedValue = undefined;
        const size = @min(self.nodes.count(), MAX_N_NODES);
        const store_values = self.store.iterator().values;
        const node_indexs = self.nodes.iterator().keys;
        for (0..size) |i| {
            const index = node_indexs[i];
            const entry = &store_values[index];
            entry_ptrs[i] = entry;
        }
        return entry_ptrs[0..size];
    }
};

test "gossip.crds_table: add contact info" {
    var kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk, true);
    const unspecified_addr = SocketAddr.unspecified();
    var legacy_contact_info = crds.LegacyContactInfo{
        .id = id,
        .gossip = unspecified_addr,
        .tvu = unspecified_addr,
        .tvu_forwards = unspecified_addr,
        .repair = unspecified_addr,
        .tpu = unspecified_addr,
        .tpu_forwards = unspecified_addr,
        .tpu_vote = unspecified_addr,
        .rpc = unspecified_addr,
        .rpc_pubsub = unspecified_addr,
        .serve_repair = unspecified_addr,
        .wallclock = 0,
        .shred_version = 0,
    };
    var crds_value = try CrdsValue.initSigned(CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    }, kp);

    var crds_table = CrdsTable.init(std.testing.allocator);
    defer crds_table.deinit();

    // test insertion
    try crds_table.insert(crds_value, 0);

    // test retrieval
    var nodes = try crds_table.get_nodes();
    try std.testing.expect(nodes.len == 1);
    switch (nodes[0].value.data) {
        .LegacyContactInfo => |info| {
            try std.testing.expect(info.id.equals(&id));
        },
        else => {
            unreachable;
        },
    }
}
