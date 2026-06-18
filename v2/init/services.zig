//! This file defines each service and the regions it requires. It is consumed
//! programmtically by build.zig to auto-build a lib for each service.
//!
//! - Every top-level public decl in this file must be a service definition.
//! - Every service must be defined in this file or it will not be spawnable.
//! - The decl name must be consistent with the filename in services/
//! - Every service definition must be a struct with `ReadOnly` and `ReadWrite`
//!   types that list the types that the service expects to find in its regions.

const lib = @import("lib");

pub const accounts_db = struct {
    pub const ReadOnly = struct {};

    pub const ReadWrite = struct {
        config: *lib.accounts_db.RootedConfig,
        ready_snapshot_in: *lib.snapshot.SnapshotDataRing,
        snapshot_metadata_out: *lib.accounts_db.RuntimeMetadata,
        account_pool: *lib.accounts_db.AccountPool,
        replay_lookups: *lib.accounts_db.AccountLookups,
        tel: *lib.telemetry.Region,
    };
};

pub const exec = struct {
    pub const ReadOnly = struct {
        replay_transaction_pool: *const lib.replay.TransactionPool,
        block_pool: *const lib.replay.BlockPool,
    };

    pub const ReadWrite = struct {
        exec_req_response: *lib.replay.ExecReqResponse,
    };
};

pub const net = struct {
    pub const ReadOnly = struct {};

    pub const ReadWrite = struct {
        gossip_pair: *lib.net.Pair,
        shred_pair: *lib.net.Pair,
        tel: *lib.telemetry.Region,
    };
};

pub const gossip = struct {
    pub const ReadOnly = struct {
        config: *const lib.gossip.Config,
    };

    pub const ReadWrite = struct {
        net_pair: *lib.net.Pair,
        gossip_to_snapshot: *lib.snapshot.SnapshotSourceRing,
        tel: *lib.telemetry.Region,
    };
};

pub const replay = struct {
    pub const ReadOnly = struct {};

    pub const ReadWrite = struct {
        scratch_memory: *[lib.replay.scratch_buffer_size]u8,
        snapshot_metadata_in: *lib.accounts_db.RuntimeMetadata,
        deshredded_in: *lib.shred.DeshredRing,
        replay_transaction_pool: *lib.replay.TransactionPool,
        block_pool: *lib.replay.BlockPool,
        exec_req_response: *lib.replay.ExecReqResponse,
        account_pool: *lib.accounts_db.AccountPool,
        account_lookups: *lib.accounts_db.AccountLookups,
        tel: *lib.telemetry.Region,
    };
};

pub const shred_receiver = struct {
    pub const ReadOnly = struct {
        config: *const lib.shred.RecvConfig,
    };

    pub const ReadWrite = struct {
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
    };
};

pub const snapshot = struct {
    pub const ReadOnly = struct {
        config: *const lib.snapshot.SnapshotConfig,
    };

    pub const ReadWrite = struct {
        source_from_gossip: *lib.snapshot.SnapshotSourceRing,
        ready_snapshot_out: *lib.snapshot.SnapshotDataRing,
        tel: *lib.telemetry.Region,
    };
};

pub const telemetry = struct {
    pub const ReadOnly = struct {};

    pub const ReadWrite = struct {
        region: *lib.telemetry.Region,
    };
};
