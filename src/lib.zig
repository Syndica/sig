pub const rpc = struct {
    // TODO: FIXME
    // pub usingnamespace @import("rpc/client.zig");
    pub const types = struct {
        pub usingnamespace @import("rpc/types.zig");
    };
};

pub const core = struct {
    pub usingnamespace @import("core/pubkey.zig");
    pub usingnamespace @import("core/account.zig");
    pub usingnamespace @import("core/transaction.zig");
    pub usingnamespace @import("core/hash.zig");
    pub usingnamespace @import("core/signature.zig");
    pub usingnamespace @import("core/time.zig");
    pub usingnamespace @import("core/hard_forks.zig");
    pub usingnamespace @import("core/shred.zig");
};

pub const accounts_db = struct {
    pub usingnamespace @import("accountsdb/db.zig");
    pub usingnamespace @import("accountsdb/bank.zig");
    pub usingnamespace @import("accountsdb/accounts_file.zig");
    pub usingnamespace @import("accountsdb/genesis_config.zig");
    pub usingnamespace @import("accountsdb/index.zig");
    pub usingnamespace @import("accountsdb/snapshots.zig");
    pub usingnamespace @import("accountsdb/sysvars.zig");
    pub usingnamespace @import("accountsdb/download.zig");
};

pub const gossip = struct {
    pub usingnamespace @import("gossip/data.zig");
    pub usingnamespace @import("gossip/table.zig");
    pub usingnamespace @import("gossip/service.zig");
    pub usingnamespace @import("gossip/message.zig");
    pub usingnamespace @import("gossip/pull_request.zig");
    pub usingnamespace @import("gossip/pull_response.zig");
    pub usingnamespace @import("gossip/shards.zig");
    pub usingnamespace @import("gossip/ping_pong.zig");
    pub usingnamespace @import("gossip/active_set.zig");
    pub usingnamespace @import("gossip/dump_service.zig");
};

pub const bloom = struct {
    pub usingnamespace @import("bloom/bit_vec.zig");
    pub usingnamespace @import("bloom/bit_set.zig");
    pub usingnamespace @import("bloom/bloom.zig");
};

pub const version = struct {
    pub usingnamespace @import("version/version.zig");
};

pub const sync = struct {
    pub usingnamespace @import("sync/channel.zig");
    pub usingnamespace @import("sync/mpmc.zig");
    pub usingnamespace @import("sync/ref.zig");
    pub usingnamespace @import("sync/mux.zig");
    pub usingnamespace @import("sync/once_cell.zig");
    pub usingnamespace @import("sync/thread_pool.zig");
};

pub const utils = struct {
    pub usingnamespace @import("utils/shortvec.zig");
    pub usingnamespace @import("utils/types.zig");
    pub usingnamespace @import("utils/varint.zig");
};

pub const trace = struct {
    pub usingnamespace @import("trace/level.zig");
    pub usingnamespace @import("trace/log.zig");
    pub usingnamespace @import("trace/entry.zig");
};

pub const common = struct {
    pub usingnamespace @import("common/lru.zig");
    pub usingnamespace @import("common/merkle_tree.zig");
};

pub const bincode = struct {
    pub usingnamespace @import("bincode/bincode.zig");
};

pub const cmd = struct {
    pub usingnamespace @import("cmd/helpers.zig");
};

pub const net = struct {
    pub usingnamespace @import("net/net.zig");
    pub usingnamespace @import("net/echo.zig");
    pub usingnamespace @import("net/packet.zig");
    pub usingnamespace @import("net/socket_utils.zig");
};

pub const prometheus = struct {
    pub usingnamespace @import("prometheus/counter.zig");
    pub usingnamespace @import("prometheus/gauge.zig");
    pub usingnamespace @import("prometheus/gauge_fn.zig");
    pub usingnamespace @import("prometheus/http.zig");
    pub usingnamespace @import("prometheus/histogram.zig");
    pub usingnamespace @import("prometheus/metric.zig");
    pub usingnamespace @import("prometheus/registry.zig");
};

pub const tvu = struct {
    pub usingnamespace @import("tvu/repair_message.zig");
    pub usingnamespace @import("tvu/repair_service.zig");
    pub usingnamespace @import("tvu/shred_receiver.zig");
};
