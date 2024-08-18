const sig = @import("../sig.zig");

const SocketAddr = sig.net.SocketAddr;
const Duration = sig.time.Duration;
const ClusterType = sig.accounts_db.genesis_config.ClusterType;

pub const Config = struct {
    // Cluster type
    cluster: ClusterType,
    // Socket to send transactions from
    socket: SocketAddr,
    // Maximum number of transactions to send in a batch
    batch_size: usize = 1,
    // Time waited between sending transaction batches
    batch_send_rate: Duration = Duration.fromSecs(1),
    // Maximum number of transactions allowed in the transaction pool
    pool_max_size: usize = 1000,
    // Time waited between processing the transaction pool
    pool_process_rate: Duration = Duration.fromSecs(1),
    // Maximum number of leaders to forward to ahead of the current leader
    max_leaders_to_send_to: usize = 5,
    // Number of consecutive leader slots (TODO: this should come from other config somewhere)
    number_of_consecutive_leader_slots: u64 = 4,
    // Maximum number of retries for a transaction whoes max_retries is null
    default_max_retries: ?usize = null,
    // Time waited between retrying transactions
    retry_rate: Duration = Duration.fromSecs(1),
};
