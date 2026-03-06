# Gossip Protocol

Solana nodes run a custom protocol over UDP that lets them discover other nodes on the network and share data across the cluster.

### Wire Format

All data sent over the Gossip Protocol is serialized using the `bincode` format:

* integers (e.g. `u8`, `u16`, `u32`, `u64`) are written using little-endian.
* enums (e.g. `enum(u32)`) are written as integers specified in their backing type.
* unions (e.g. `union(enum(u8)){ a: A, b: B }`) first write their active enum tag, then the variant itself.
* structs (e.g. `struct{ a: A, b: B }`) simply write each field one by one in declaration order.
* fixed-sized arrays (e.g. `[32]u8`) simply write each element one by one. 
* dynamically-sized arrays (e.g. `List(T)`) first write a `u64` of the array len, then each of the array elements one by one.
* variable-sized integers (e.g. `VarInt(u64)`) are written iteratively: take the bottom 7 bits of the backing integer as `x` then remove them from backing integer with `>> 7`. If there's more bits left, set the 8th bit in `x`. Write out `x` as a byte and repeat until no more bits left.
* short-vecs (e.g. `ShortVec(T)`) are like `List(T)` but their length is written as a `VarInt(u16)` instead of a `u64`.
* optionals (e.g. `?T`) either write a `0` byte if empty/null, or `1` byte followed by the value.
* bit-vecs (e.g. `BitVec(u64)`) is defined as `struct{ words: ?List(T), bits: u64 }`, holding the bits themselves as `T` words, and the number of bits represented by the words.

### Setup

A node is identified by its own public + private key pair. The primary information nodes share is their `ContactInfo`. This is a type that contains the node's public key, along with all the service socket addresses `(ip, port)` that the node's identity is running (e.g. Gossip, RPC, Turbine, Votes, Transactions, etc.).

To advertise the node's Gossip service on a given port, it first needs to know its own public IP address. Solana labs provides entrypoint nodes a new gossip node can connect to for each network cluster.

| Network  | Entrypoint |
| -------- | ------- |
| mainnet  | `entrypoint.mainnet-beta.solana.com:8001`   |
| devnet   | `entrypoint.devnet.solana.com:8001`     |
| testnet  | `entrypoint.testnet.solana.com:8001`   |

These entrypoints also run an "Echo Server" that 1. tests for port connectivity to the client and 2. echos back the client's public IP address. First, connect to the entrypoint over TCP and send a `bincode` serialized EchoMessage:

```zig
const EchoMessage = struct {
    _hidden_header: u32 = 0,
    tcp_ports: [4]u16,
    udp_ports: [4]u16,
    _hidden_trailer: u8 = '\n',
};
```

The reason for the hidden fields is that agave wants to handle users [accidently sending HTTP requests](https://github.com/anza-xyz/agave/blob/v3.1.9/net-utils/src/ip_echo_server.rs#L60-L98)... Regardless, the ports specified will be tested by the echo server; sending a zero-byte message for the udp ports, and simply opening then closing a connection for the tcp ports. The port testing isn't needed for the echo server to return your public IP address, so they can be left zero in practice.

Once it receives the `EchoMessage`, it responds with a bincode serialized `EchoResponse`:
```zig
const EchoResponse = struct {
    _hidden_header: u32,
    addr: IpAddr,
    shred_version: ?u16,
};

const IpAddr = union(enum(u32)) {
    v4: [4]u8,
    v6: [16]u8,
};
```

### Gossip Table

A gossip node's main purpose to is communicate `CrdsValue`s. These `CrdsValue`s are signed by their origin producer node and contain 1 of 14 different data types.
```zig
const CrdsValue = struct {
    // ed25519 signature of serialized `data` bytes
    signature: [64]u8,
    data: CrdsData,
};

const CrdsData = union(enum(u32)) {
    _legacy_contact_info: LegacyContactInfo, // deprecated
    vote: Vote, 
    lowest_repair_slot: LowestSlot,
    _legacy_snapshot_hashes: AccountsHashes, // deprecated
    _account_hashes: AccountsHashes, // deprecated
    epoch_frozen_slots: EpochSlots,
    _legacy_version: LegacyVersion, // deprecated
    _version: Version, // deprecated
    _node_instance: NodeInstance, // deprecated
    duplicate_shred: DuplicateShred,
    snapshot_hashes: SnapshotHashes,
    contact_info: ContactInfo,
    restart_last_voted_fork_slots: RestartLastVotedForkSlots,
    restart_heaviest_fork: RestartHeaviestFork,
};
```

<details>
<summary>The specific `CrdsData` bincode type definitions</summary>

```zig
/// Deprecated.
const LegacyContactInfo = struct {
    origin: [32]u8, // pubkey
    gossip: SocketAddr,
    tvu: SocketAddr,
    tvu_quic: SocketAddr,
    serve_repair_quic: SocketAddr,
    tpu: SocketAddr,
    tpu_forwards: SocketAddr,
    tpu_vote: SocketAddr,
    rpc: SocketAddr,
    rpc_pubsub: SocketAddr,
    serve_repair: SocketAddr,
    wallclock: u64, // < 1_000_000_000_000_000
    shred_version: u16,

    const SocketAddr = union(enum(u32)) {
        v4: struct {
            ip: [4]u8,
            port: u16,
        },
        v6: struct {
            ip: [16]u8,
            port: u16,
        },
    };
};

const Vote = struct {
    index: u8, // <= 12
    origin: [32]u8, // pubkey
    transaction: struct {
        // signatures.len <= message.header.num_required_signatures
        // signatures.len <= message.account_keys.len
        signatures: ShortVec([64]u8), 
        message: struct {
            // num_required_signatures + num_readonly_unsigned_accounts <= account_keys.len
            // num_readonly_signed_accounts < num_required_signatures
            header: struct {
                num_required_signatures: u8,
                num_readonly_signed_accounts: u8,
                num_readonly_unsigned_accounts: u8,
            },
            account_keys: ShortVec([32]u8), // pubkeys
            recent_blockhash: [32]u8, // sha256
            instructions: ShortVec(struct {
                // i > 0 and i < account_keys.len
                program_id_idx: u8,
                // i < account_keys.len
                account_indexes: ShortVec(u8),
                data: ShortVec(u8),
            })
        },
    },
    wallclock: u64, // < 1_000_000_000_000_000
};

/// The `lowest_slot` the `origin` is serving shreds for over its serve_repair address. 
const LowestSlot = struct {
    _index: u8, // deprecated: (must be 0)
    origin: [32]u8, // pubkey
    _root_slot: u64, // deprecated. > 0
    lowet_slot: u64, // < 1_000_000_000_000_000
    _slots: List(u64), // deprecated (must be empty)
    _stashes: List(struct { // deprecated (must be empty)
        first_slot: u64, // < 1_000_000_000_000_000
        compression: enum(u32) {
            uncompressed,
            gzip,
            bzip2,
        },
        bytes: List(u8),
    }),
    wallclock: u64, // < 1_000_000_000_000_000
};

/// Deprecated.
const AccountsHashes = struct {
    origin: [32]u8, // pubkey
    slot_hashes: List(struct {
        slot: u64, // < 1_000_000_000_000_000
        hash: [32]u8, // sha256
    }),
    wallclock: u64, // < 1_000_000_000_000_000
};

/// The set of slots a validator node has frozen/processed within an epoch.
/// A max of 255 EpochSlot instances are tracked per node. And only staked nodes publishing this.
const EpochSlots = struct {
    index: u8, // <= 255
    origin: [32]u8, // pubkey
    slots: enum(u32) {
        flate2: struct {
            first_slot: u64, // < 1_000_000_000_000_000
            num_slots: u64, // < 16_384
            compressed_offset_bitvec: List(u8),
        },
        uncompressed: struct{
            first_slot: u64, // < 1_000_000_000_000_000
            num_slots: u64, // < 16_384
            offset_is_frozen: BitVec(u8), // .len % 8 == 0, 
        },
    },
    wallclock: u64, // < 1_000_000_000_000_000
};

/// Deprecated.
const LegacyVersion = struct {
    origin: [32]u8, // pubkey
    wallclock: u64, // < 1_000_000_000_000_000
    major: u16,
    minor: u16,
    patch: u16,
    commit: ?u32, // first 4-bytes of git sha commit hash
};

/// Deprecated.
const Version = struct {
    origin: [32]u8, // pubkey
    wallclock: u64, // < 1_000_000_000_000_000
    major: u16,
    minor: u16,
    patch: u16,
    commit: ?u32, // first 4-bytes of git sha commit hash
    feature_set: u32, // first 4-bytes of FeatureSet identifier
};

/// Deprecated.
const NodeInstance = struct {
    origin: [32]u8, // pubkey
    wallclock: u64, // < 1_000_000_000_000_000
    created: u64, // wallclock timestamp when node was created
    token: u64, // randomly generated value at node creation
};

const DuplicateShred = struct {
    origin: [32]u8, // pubkey
    wallclock: u64, // < 1_000_000_000_000_000
    slot: u64, // < 1_000_000_000_000_000
    _unused: u32,
    _unused_shred_type: u8,
    num_chunks: u8, // 
    chunk_index: u8,
    chunk: List(u8)
};

/// What snapshots are available for download under the node's RPC contact
/// Full: http://{rpc_ip}:{rpc_port}/snapshot-{slot}-{hash}.tar.zst
/// Incremental: http://{rpc_ip}:{rpc_port}/incremental-snapshot-{slot}-{hash}.tar.zst
const SnapshotHashes = struct {
    origin: [32]u8, // pubkey
    full: struct{
        slot: u64, // < 1_000_000_000_000_000
        hash: [32]u8, // sha256
    },
    incremental: List(struct {
        slot: u64, // < 1_000_000_000_000_000
        hash: [32]u8, // sha256
    }),
    wallclock: u64, // < 1_000_000_000_000_000
};

const ContactInfo = struct {

};

/// Phase 1 of the wen-restart protocol (SIMD-0046).
/// When restarting, each node broadcasts the last fork they voted on (as a set of slots).
/// The slots are represented as either run-length-encoded slot ranges or a bitvec of slots.
/// At most 65535 slots are allowed to be broadcasted & this serialized structs stays <= 824 bytes.
///
/// It uses this to track which slots have >42% of stake voted on it, and what % of stake is voting.
/// Once 80% of stake has voted and all slot shreds have been repaired, it moves to phase 2.
const RestartLastVotedForkSlots = struct {
    origin: [32]u8, // pubkey
    wallclock: u64, // < 1_000_000_000_000_000
    offsets: union(enum(u32)) {
        run_length_encoded: List(u16), // rle[i] slots ARE voted on, rle[i+1] AREN'T voted on, i+=2
        raw_offset_mask: BitVec(u8), // mask[bit=i] == {last_voted_slot + i} was voted on 
    },
    last_voted_slot: u64, // < 1_000_000_000_000_000
    last_voted_hash: [32]u8, // sha256 slot hash
    shred_version: u16, 
};

/// Phase 2 of the wen-restart protocol (SIMD-0046).
/// Once the stake-heaviest fork is decided, broadcast its (slot, hash).
/// A (slot, hash) pair becomes heaviest when its stake >= `active_stake − total_stake × 0.38`.
/// At that point, the nodes creates a new incremental snapshot compuets a new shred_version. 
const RestartHeaviestFork = struct {
    origin: [32]u8, // pubkey
    wallclock: u64, // < 1_000_000_000_000_000
    last_slot: u64, // < 1_000_000_000_000_000
    last_hash: [32]u8, // sha256 slot hash
    observed_stake: u64,
    shred_version: u16,
};
```

</details>

TODO:
- tracking (Ping, Pong), live data (Push, Prune), existing data (PullReq, PullResp) 