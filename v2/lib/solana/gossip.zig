const std = @import("std");
const lib = @import("../lib.zig");

const bincode = lib.solana.bincode;

const Signature = lib.solana.Signature;
const Pubkey = lib.solana.Pubkey;
const Hash = lib.solana.Hash;
const Slot = lib.solana.Slot;
const SlotAndHash = lib.solana.SlotAndHash;

pub const EchoMessage = struct {
    _header: u32 = 0,
    tcp_ports: [4]u16,
    udp_ports: [4]u16,
    _trailer: u8 = '\n',
};

pub const EchoResponse = struct {
    _header: u32 = 0,
    public_ip: IpAddr,
    shred_version: ?u16,
};

pub const IpAddr = union(enum(u32)) {
    v4: [4]u8,
    v6: [16]u8,
};

pub const BloomFilter = struct {
    keys: bincode.Vec(u64),
    bits: bincode.BitVec(u64),
    bits_set: u64,

    pub fn getBitPos(self: *const BloomFilter, key: u64, bytes: []const u8) u64 {
        var h = std.hash.Fnv1a_64{ .value = key };
        h.update(bytes);
        return h.final() % self.bits.capacity;
    }

    pub fn add(self: *BloomFilter, bytes: []const u8) void {
        if (self.bits.capacity == 0 or self.bits.words.len == 0) return;
        for (self.keys.items) |key| {
            const pos = self.getBitPos(key, bytes);
            self.bits_set += self.bits.set(pos);
        }
    }

    pub fn contains(self: *const BloomFilter, bytes: []const u8) bool {
        if (self.bits.capacity == 0 or self.bits.words.len == 0) return false;
        for (self.keys.items) |key| {
            const pos = self.getBitPos(key, bytes);
            if (self.bits.get(pos) == 0) return false;
        }
        return true;
    }
};

/// Gossip nodes communicate with this message type (bincode serialized) to pass GossipValues around.
pub const GossipMessage = union(enum(u32)) {
    pull_request: struct {
        ignoring: BloomFilter,
        mask: u64,
        mask_bits: u32,
        contact_info: GossipValue,
    },
    pull_response: struct {
        from: Pubkey,
        values: bincode.Vec(GossipValue),
    },
    push_message: struct {
        from: Pubkey,
        values: bincode.Vec(GossipValue),
    },
    prune_message: struct {
        from: Pubkey,
        data: struct {
            pubkey: Pubkey,
            prunes: bincode.Vec(Pubkey),
            signature: Signature,
            destination: Pubkey,
            wallclock: u64,
        },
    },
    ping_message: struct {
        from: Pubkey,
        token: [32]u8,
        signature: Signature,
    },
    pong_message: struct {
        from: Pubkey,
        hash: Hash,
        signature: Signature,
    },
};

/// Gossip values are (bincode serialized) gossip data signed by `data.*.from` Pubkey identity.
pub const GossipValue = struct {
    signature: Signature,
    data: GossipData,
};

pub const GossipData = union(enum(u32)) {
    legacy_contact_info: bincode.Deprecated,
    vote: Vote,
    lowest_slot: LowestSlot,
    legacy_snapshot_hashes: bincode.Deprecated,
    account_hashes: bincode.Deprecated,
    epoch_slots: struct {
        index: u8,
        from: Pubkey,
        slots: bincode.Vec(union(enum(u32)) {
            flate2: struct {
                first_slot: Slot,
                num_slots: u64,
                compressed: bincode.Vec(u8),
            },
            uncompressed: struct {
                first_slot: Slot,
                num_slots: u64,
                slots: bincode.BitVec(u8),
            },
        }),
        wallclock: u64,
    },
    legacy_version: bincode.Deprecated,
    version: bincode.Deprecated,
    node_instance: bincode.Deprecated,
    duplicate_shred: DuplicateShred,
    snapshot_hashes: SnapshotHashes,
    contact_info: ContactInfo,
    /// Deprecated and unused. But nodes may still send them for us to ignore.
    restart_last_voted_fork: struct {
        from: Pubkey,
        wallclock: u64,
        offsets: bincode.Vec(union(enum(u32)) {
            rle: bincode.Vec(bincode.VarInt(u16)),
            raw: bincode.BitVec(u8),
        }),
        last_voted: SlotAndHash,
        shred_version: u16,
    },
    /// Deprecated and unused. But nodes may still send them for us to ignore.
    restart_heaviest_fork: struct {
        from: Pubkey,
        wallclock: u64,
        last_slot: SlotAndHash,
        observed_stake: u64,
        shred_version: u16,
    },
};

/// Sent out by nodes to indicate the lowest slot they're serving shreds for over repair.
pub const LowestSlot = struct {
    index: u8,
    from: Pubkey,
    _root: Slot, // deprecated
    lowest: Slot,
    _slots: bincode.Vec(Slot), // deprecated
    _stashes: bincode.Vec(struct { // deprecated
        first_slot: Slot,
        compression: enum(u32) {
            uncompressed,
            gzip,
            bzip2,
        },
        bytes: bincode.Vec(u8),
    }),
    wallclock: u64,
};

/// Sent out by nodes to indicate which snapshots they have available for download via their
/// `ContactInfo.socket_map.get(.rpc)` address
pub const SnapshotHashes = struct {
    from: Pubkey,
    full: SlotAndHash,
    incremental: bincode.Vec(SlotAndHash),
    wallclock: u64,
};

/// A vote transaction from a node submitted as a GossipValue in the protocol.
// TODO: move this into lib/solana/transaction.zig for similar Message types used in shred recv.
pub const Vote = struct {
    index: u8,
    from: Pubkey,
    transaction: struct {
        signatures: bincode.ShortVec(Signature),
        message: struct {
            num_signatures: u8,
            num_readonly_signed: u8,
            num_readonly_unsigned: u8,
            accounts: bincode.ShortVec(Pubkey),
            recent_blockhash: Hash,
            instructions: bincode.ShortVec(struct {
                program_id: u8,
                accounts: bincode.ShortVec(u8),
                data: bincode.ShortVec(u8),
            }),
        },
    },
    wallclock: u64,
};

/// Sent out by nodes when they discover a duplicate shred.
pub const DuplicateShred = struct {
    index: u16,
    from: Pubkey,
    wallclock: u64,
    slot: Slot,
    _unused: u32,
    _unused_shred_type: u8, // explicitly not an enum to avoid specific tag checks
    num_chunks: u8,
    chunk_idx: u8,
    chunk: bincode.Vec(u8),
};

/// The addresses and service information for a gossip node instance participating in the cluster.
/// Sent out by nodes to update their reachable service addresses + keep their gossip connection
/// alive.
pub const ContactInfo = struct {
    from: Pubkey,
    wallclock: bincode.VarInt(u64),
    created: u64,
    shred_version: u16,
    major: bincode.VarInt(u16),
    minor: bincode.VarInt(u16),
    patch: bincode.VarInt(u16),
    commit: u32,
    feature_set: u32,
    client_id: bincode.VarInt(u16),
    prerelease: union(enum(u32)) {
        stable,
        release_candidate: u16,
        beta: u16,
        alpha: u16,
    },
    socket_map: SocketMap,
    extensions: bincode.ShortVec(struct {
        type: u8,
        bytes: bincode.ShortVec(u8),
    }),
};

/// A map of validator services (e.g. serve_repair, rpc, gossip, tvu) to `Address`
/// that a given gossip node identity broadcasts to the cluster.
pub const SocketMap = struct {
    ips: bincode.ShortVec(IpAddr),
    entries: bincode.ShortVec(SocketEntry),

    const SocketEntry = struct {
        key: Key,
        ip_idx: u8,
        port_offset: bincode.VarInt(u16),
    };

    pub const Key = enum(u8) {
        gossip,
        serve_repair_quic,
        rpc,
        rpc_pubsub,
        serve_repair,
        tpu,
        tpu_forwards,
        tpu_forwards_quic,
        tpu_quic,
        tpu_vote,
        tvu,
        tvu_quic,
        tpu_vote_quic,
        alpenglow,
        _,
    };

    pub fn get(self: *const SocketMap, key: Key) ?std.net.Address {
        var port: u16 = 0;
        for (self.entries.items) |e| {
            port += e.port_offset.value;
            if (e.key != key) continue;
            if (e.ip_idx >= self.ips.items.len) continue;
            return switch (self.ips.items[e.ip_idx]) {
                .v4 => |ip| .initIp4(ip, port),
                .v6 => |ip| .initIp6(ip, port, 0, 0),
            };
        }
        return null;
    }

    pub const Builder = struct {
        ips: [max_count]IpAddr = undefined,
        num_ips: u8 = 0,
        entries: [max_count]SocketEntry = undefined,
        num_entries: u8 = 0,

        const max_count = std.meta.fields(Key).len;

        pub fn set(self: *Builder, key: Key, addr: std.net.Address) void {
            // Address.ip -> IpAddr, then dedup
            const ip: IpAddr = switch (addr.any.family) {
                std.posix.AF.INET => .{ .v4 = @bitCast(addr.in.sa.addr) },
                std.posix.AF.INET6 => .{ .v6 = addr.in6.sa.addr },
                else => unreachable,
            };

            const ip_idx = for (self.ips[0..self.num_ips], 0..) |existing, i| {
                if (lib.util.eql(existing, ip)) break i;
            } else blk: {
                std.debug.assert(self.num_ips < self.ips.len);
                defer self.num_ips += 1;
                break :blk self.num_ips;
            };

            // (Key + Address.port) -> SocketEntry, then dedup
            const entry: SocketEntry = .{
                .key = key,
                .ip_idx = @intCast(ip_idx),
                .port_offset = .{ .value = addr.getPort() },
            };
            const entry_idx = for (self.entries[0..self.num_entries], 0..) |existing, i| {
                if (lib.util.eql(existing, entry)) break i;
            } else blk: {
                std.debug.assert(self.num_entries < self.entries.len);
                defer self.num_entries += 1;
                break :blk self.num_entries;
            };

            self.ips[ip_idx] = ip;
            self.entries[entry_idx] = entry;
        }

        /// Prepares the builder's internal data structures to be used inside a ContactInfo,
        /// then returns a SocketMap instance which refers back into the Builder's memory.
        /// `Builder.set()` must no longer be called after this.
        pub fn asSocketMap(self: *Builder) SocketMap {
            // sort entries by port
            const entries = self.entries[0..self.num_entries];
            std.mem.sort(SocketEntry, entries, {}, struct {
                fn lessThan(_: void, a: SocketEntry, b: SocketEntry) bool {
                    return a.port_offset.value < b.port_offset.value;
                }
            }.lessThan);

            // then convert ports into offsets of each other
            var port: u16 = 0;
            for (entries) |*e| {
                e.port_offset.value -= port;
                port += e.port_offset.value;
            }

            return .{
                .ips = .{ .items = self.ips[0..self.num_ips] },
                .entries = .{ .items = entries },
            };
        }
    };
};
