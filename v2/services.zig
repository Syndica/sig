//! This file defines each service and the regions it requires. It is consumed
//! programmtically by build.zig to auto-build a lib for each service.
//!
//! - Every top-level public decl in this file must be a service definition.
//! - Every service must be defined in this file or it will not be spawnable.
//! - The decl name must be consistent with the filename in services/
//! - Every service definition must be a struct with `ReadOnly` and `ReadWrite`
//!   types that list the types that the service expects to find in its regions.

const lib = @import("lib");
const accounts_db_api = @import("accounts_db_api");
const shred_api = @import("shred_api");
const gossip_api = @import("gossip_api");
const snapshot_api = @import("snapshot_api");
const replay_api = @import("replay_api");

pub const accounts_db = struct {
    pub const components = &.{"accounts_db"};

    pub const ReadOnly = struct {};

    pub const ReadWrite = struct {
        config: *accounts_db_api.RootedConfig,
        ready_snapshot_in: *snapshot_api.SnapshotDataRing,
        snapshot_metadata_out: *accounts_db_api.RuntimeMetadata,
        account_pool: *accounts_db_api.AccountPool,
        replay_lookups: *accounts_db_api.AccountLookups,
        tel: *lib.telemetry.Region,
    };
};

pub const exec = struct {
    pub const components = &.{"runtime"};

    pub const ReadOnly = struct {
        replay_transaction_pool: *const replay_api.TransactionPool,
        block_pool: *const replay_api.BlockPool,
    };

    pub const ReadWrite = struct {
        exec_req_response: *replay_api.ExecReqResponse,
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
    pub const components = &.{"gossip"};

    pub const ReadOnly = struct {
        config: *const gossip_api.Config,
    };

    pub const ReadWrite = struct {
        net_pair: *lib.net.Pair,
        gossip_to_snapshot: *snapshot_api.SnapshotSourceRing,
        tel: *lib.telemetry.Region,
    };
};

pub const replay = struct {
    pub const components = &.{"replay"};

    pub const ReadOnly = struct {};

    pub const ReadWrite = struct {
        snapshot_metadata_in: *accounts_db_api.RuntimeMetadata,
        deshredded_in: *shred_api.DeshredRing,
        replay_transaction_pool: *replay_api.TransactionPool,
        block_pool: *replay_api.BlockPool,
        exec_req_response: *replay_api.ExecReqResponse,
        tel: *lib.telemetry.Region,
    };
};

pub const shred_receiver = struct {
    pub const components = &.{"shred"};

    pub const ReadOnly = struct {
        config: *const shred_api.RecvConfig,
    };

    pub const ReadWrite = struct {
        /// Gets slot (& soon leader-schedule info) from replay / runtime init.
        snapshot_metadata: *accounts_db_api.RuntimeMetadata,

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
        deshredded_out: *shred_api.DeshredRing,

        tel: *lib.telemetry.Region,
    };
};

pub const snapshot = struct {
    pub const components = &.{"snapshot"};

    pub const ReadOnly = struct {
        config: *const snapshot_api.SnapshotConfig,
    };

    pub const ReadWrite = struct {
        source_from_gossip: *snapshot_api.SnapshotSourceRing,
        ready_snapshot_out: *snapshot_api.SnapshotDataRing,
        tel: *lib.telemetry.Region,
    };
};

pub const telemetry = struct {
    pub const ReadOnly = struct {};

    pub const ReadWrite = struct {
        region: *lib.telemetry.Region,
    };
};
