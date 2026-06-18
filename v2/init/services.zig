const lib = @import("lib");
const topology = lib.topology;

const ServiceSpec = topology.ServiceSpec;

pub const accounts_db: ServiceSpec = .{
    .ReadOnly = struct {},
    .ReadWrite = struct {
        config: *lib.accounts_db.RootedConfig,
        ready_snapshot_in: *lib.snapshot.SnapshotDataRing,
        snapshot_metadata_out: *lib.accounts_db.RuntimeMetadata,
        account_pool: *lib.accounts_db.AccountPool,
        replay_lookups: *lib.accounts_db.AccountLookups,
        tel: *lib.telemetry.Region,
    },
};

pub const exec: ServiceSpec = .{
    .ReadOnly = struct {
        replay_transaction_pool: *const lib.replay.TransactionPool,
        block_pool: *const lib.replay.BlockPool,
    },
    .ReadWrite = struct {
        exec_req_response: *lib.replay.ExecReqResponse,
    },
};

pub const net: ServiceSpec = .{
    .ReadOnly = struct {},
    .ReadWrite = struct {
        gossip_pair: *lib.net.Pair,
        shred_pair: *lib.net.Pair,
        tel: *lib.telemetry.Region,
    },
};

pub const gossip: ServiceSpec = .{
    .ReadOnly = struct {
        config: *const lib.gossip.Config,
    },
    .ReadWrite = struct {
        net_pair: *lib.net.Pair,
        gossip_to_snapshot: *lib.snapshot.SnapshotSourceRing,
        tel: *lib.telemetry.Region,
    },
};

pub const replay: ServiceSpec = .{
    .ReadOnly = struct {},
    .ReadWrite = struct {
        scratch_memory: *[lib.replay.scratch_buffer_size]u8,
        snapshot_metadata_in: *lib.accounts_db.RuntimeMetadata,
        deshredded_in: *lib.shred.DeshredRing,
        replay_transaction_pool: *lib.replay.TransactionPool,
        block_pool: *lib.replay.BlockPool,
        exec_req_response: *lib.replay.ExecReqResponse,
        account_pool: *lib.accounts_db.AccountPool,
        account_lookups: *lib.accounts_db.AccountLookups,
        tel: *lib.telemetry.Region,
    },
};

pub const shred_receiver: ServiceSpec = .{
    .ReadOnly = struct {
        config: *const lib.shred.RecvConfig,
    },
    .ReadWrite = struct {
        /// Gets slot (& soon leader-schedule info) from replay / runtime init.
        snapshot_metadata: *lib.accounts_db.RuntimeMetadata,

        /// Transaction Validation Unit (TVU) UDP socket, i.e. where we receive
        /// shreds. This is typically port 8002. While we've obtained a net
        /// Pair, we only currently receive on this. I believe once we support
        /// retransmit, we will be sending on it too.
        tvu_socket: *lib.net.Pair,

        /// Where we send our deshredded FEC (Forward Error Correction) sets to
        /// be assembled for replay. FEC sets will be sent out as they complete.
        ///
        /// NOTE: it will be more performant in future to only send headers down
        /// the ring buffer, and write to a shared fec-set pool.
        deshredded_out: *lib.shred.DeshredRing,

        tel: *lib.telemetry.Region,
    },
};

pub const snapshot: ServiceSpec = .{
    .ReadOnly = struct {
        config: *const lib.snapshot.SnapshotConfig,
    },
    .ReadWrite = struct {
        source_from_gossip: *lib.snapshot.SnapshotSourceRing,
        ready_snapshot_out: *lib.snapshot.SnapshotDataRing,
        tel: *lib.telemetry.Region,
    },
};

pub const telemetry: ServiceSpec = .{
    .ReadOnly = struct {},
    .ReadWrite = struct {
        region: *lib.telemetry.Region,
    },
};
