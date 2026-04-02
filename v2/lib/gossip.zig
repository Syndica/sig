const std = @import("std");
const lib = @import("lib.zig");

pub const bincode = @import("gossip/bincode.zig");
pub const GossipNode = @import("gossip/node.zig").GossipNode;

const Signature = lib.solana.Signature;
const Pubkey = lib.solana.Pubkey;
const Hash = lib.solana.Hash;
const Slot = lib.solana.Slot;

const Ring = lib.ipc.Ring;

pub const SnapshotQueue = extern struct {
    incoming: Incoming,
    outgoing: Outgoing,

    pub const Incoming = Ring(1024, Entry);
    pub const Outgoing = Ring(1, SlotAndHash);

    pub const Entry = extern struct {
        slot: Slot,
        hash: Hash,
        rpc_address: Address,
    };
};

/// Extern struct compatibility for stdlib KeyPair type
/// TODO: move this to signer service.
pub const KeyPair = extern struct {
    pubkey: Pubkey,
    private: [64]u8,

    pub fn fromKeyPair(kp: std.crypto.sign.Ed25519.KeyPair) KeyPair {
        return .{
            .pubkey = .fromPublicKey(&kp.public_key),
            .private = kp.secret_key.toBytes(),
        };
    }

    pub fn sign(self: *const KeyPair, msg: []const u8) !Signature {
        const kp: std.crypto.sign.Ed25519.KeyPair = .{
            .public_key = try .fromBytes(self.pubkey.data),
            .secret_key = try .fromBytes(self.private),
        };
        return .fromSignature(try kp.sign(msg, null));
    }
};

/// Read-only config information needed to run a gossip service instance.
pub const Config = extern struct {
    keypair: KeyPair,
    cluster_info: ClusterInfo,
    turbine_recv_port: u16,
};

// For std.meta.eql compatibility inside `serviceMap` & defined repr across processes
pub const Address = extern struct {
    is_v6: bool,
    ip: [16]u8,
    port: u16,

    pub fn fromNetAddress(net_addr: std.net.Address) Address {
        return .{
            .is_v6 = net_addr.any.family == std.posix.AF.INET6,
            .ip = switch (net_addr.any.family) {
                std.posix.AF.INET6 => net_addr.in6.sa.addr,
                std.posix.AF.INET => @bitCast([_]u32{ net_addr.in.sa.addr, 0, 0, 0 }),
                else => unreachable,
            },
            .port = net_addr.getPort(),
        };
    }

    pub fn toNetAddress(self: *const Address) std.net.Address {
        if (self.is_v6) return .initIp6(self.ip, self.port, 0, 0);
        return .initIp4(self.ip[0..4].*, self.port);
    }

    pub fn format(self: Address, w: *std.Io.Writer) !void {
        return self.toNetAddress().format(w);
    }

    pub fn withPort(self: Address, new_port: u16) Address {
        return .{ .is_v6 = self.is_v6, .ip = self.ip, .port = new_port };
    }
};

/// Bootstrapping network information needed to run a Gossip Node
pub const ClusterInfo = extern struct {
    public_ip: Address,
    shred_version: u16,
    entry_addrs_len: u8,
    entry_addrs: [MAX_ENTRY_ADDRS]Address,

    pub const MAX_ENTRY_ADDRS = 16;

    pub fn getEntryAddresses(self: *const ClusterInfo) []const Address {
        return self.entry_addrs[0..self.entry_addrs_len];
    }

    pub fn getFromEcho(gossip_port: u16, cluster: lib.solana.Cluster) !ClusterInfo {
        var result: ClusterInfo = undefined;
        result.entry_addrs_len = 0;

        for (cluster.getEntrypoints()) |entrypoint| {
            const split = std.mem.indexOfScalar(u8, entrypoint, ':') orelse continue;
            const port = std.fmt.parseInt(u16, entrypoint[split + 1 ..], 10) catch continue;

            var addr_buf: [4096]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&addr_buf);
            const addr_list =
                std.net.getAddressList(fba.allocator(), entrypoint[0..split], port) catch continue;
            defer addr_list.deinit();

            for (addr_list.addrs) |entry_addr| {
                if (result.entry_addrs_len >= MAX_ENTRY_ADDRS) break;

                const socket = std.posix.socket(
                    entry_addr.any.family,
                    std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC,
                    std.posix.IPPROTO.TCP,
                ) catch continue;
                defer std.posix.close(socket);

                // set timeout of 1s for connect, read, write.
                const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
                std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv) catch
                    continue;
                std.posix.connect(socket, &entry_addr.any, entry_addr.getOsSockLen()) catch {
                    continue;
                };

                // Used for writing, then for reading.
                var io_buf: [4096]u8 = undefined;

                var stream_writer = std.net.Stream.writer(.{ .handle = socket }, &io_buf);
                const writer = &stream_writer.interface;
                bincode.write(writer, EchoMessage{
                    .tcp_ports = @as([4]u16, @splat(0)),
                    .udp_ports = @as([4]u16, @splat(0)),
                }) catch continue;
                writer.flush() catch continue;

                var stream_reader = std.net.Stream.reader(.{ .handle = socket }, &io_buf);
                const reader: *std.Io.Reader = stream_reader.interface();
                var stub_fba = std.heap.FixedBufferAllocator.init(&.{});
                const resp = bincode.read(&stub_fba, reader, EchoResponse) catch continue;

                const shred_version = resp.shred_version orelse 0;
                const public_ip: Address = switch (resp.public_ip) {
                    .v4 => |ip| .fromNetAddress(.initIp4(ip, gossip_port)),
                    .v6 => |ip| .fromNetAddress(.initIp6(ip, gossip_port, 0, 0)),
                };

                // First successful echo sets public_ip and shred_version.
                // Subsequent echoes must return the same shred_version.
                if (result.entry_addrs_len == 0) {
                    result.public_ip = public_ip;
                    result.shred_version = shred_version;
                } else if (shred_version != result.shred_version) {
                    continue;
                }

                const new_entry_addr: Address = .fromNetAddress(entry_addr);
                const exists = for (result.getEntryAddresses()) |e| {
                    if (std.meta.eql(e, new_entry_addr)) break true;
                } else false;

                // Only accumulate if entry address isn't a duplicate.
                if (!exists) {
                    result.entry_addrs[result.entry_addrs_len] = new_entry_addr;
                    result.entry_addrs_len += 1;
                }

                // only one resolved address per entrypoint hostname
                break;
            }
        }

        if (result.entry_addrs_len == 0) return error.NoValidEntrypoint;
        return result;
    }

    const EchoMessage = struct {
        _header: u32 = 0,
        tcp_ports: [4]u16,
        udp_ports: [4]u16,
        _trailer: u8 = '\n',
    };

    const EchoResponse = struct {
        _header: u32 = 0,
        public_ip: IpAddr,
        shred_version: ?u16,
    };
};

// ---- Gossip Protocol type definitions ----

const IpAddr = union(enum(u32)) {
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
    lowest_slot: struct {
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
    },
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
    duplicate_shred: struct {
        index: u16,
        from: Pubkey,
        wallclock: u64,
        slot: Slot,
        _unused: u32,
        _unused_shred_type: u8, // explicitly not an enum to avoid specific tag checks
        num_chunks: u8,
        chunk_idx: u8,
        chunk: bincode.Vec(u8),
    },
    snapshot_hashes: struct {
        from: Pubkey,
        full: SlotAndHash,
        incremental: bincode.Vec(SlotAndHash),
        wallclock: u64,
    },
    contact_info: ContactInfo,
    /// Deprecated and unused. But nodes may still send them for us to addExpired.
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
    /// Deprecated and unused. But nodes may still send them for us to addExpired.
    restart_heaviest_fork: struct {
        from: Pubkey,
        wallclock: u64,
        last_slot: SlotAndHash,
        observed_stake: u64,
        shred_version: u16,
    },
};

pub const SlotAndHash = extern struct {
    slot: Slot,
    hash: Hash,
};

/// A vote transaction from a node submitted as a GossipValue in the protocol.
// TODO: use same type definition for Consensus service.
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

/// The addresses and service information for a gossip node instance participating in the cluster.
/// Its handled specially in the gossip protocol, so the concrete type definition is exported instead
/// of living only in GossipData.
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
    entries: bincode.ShortVec(Entry),

    const Entry = struct {
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
        entries: [max_count]Entry = undefined,
        num_entries: u8 = 0,

        const max_count = std.meta.fields(Key).len;

        pub fn set(self: *Builder, key: Key, addr: Address) void {
            // Address.ip -> IpAddr, then dedup
            const ip: IpAddr = if (addr.is_v6) .{ .v6 = addr.ip } else .{ .v4 = addr.ip[0..4].* };
            const ip_idx = for (self.ips[0..self.num_ips], 0..) |existing, i| {
                if (std.meta.eql(existing, ip)) break i;
            } else blk: {
                std.debug.assert(self.num_ips < self.ips.len);
                defer self.num_ips += 1;
                break :blk self.num_ips;
            };

            // (Key + Address.port) -> SocketEntry, then dedup
            const entry: Entry = .{
                .key = key,
                .ip_idx = @intCast(ip_idx),
                .port_offset = .{ .value = addr.port },
            };
            const entry_idx = for (self.entries[0..self.num_entries], 0..) |existing, i| {
                if (std.meta.eql(existing, entry)) break i;
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
            std.mem.sort(Entry, entries, {}, struct {
                fn lessThan(_: void, a: Entry, b: Entry) bool {
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
