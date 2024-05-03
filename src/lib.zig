const std = @import("std");

pub const rpc = struct {
    // TODO: FIXME
    // pub usingnamespace @import("rpc/client.zig");
    pub const types = @import("rpc/types.zig");
};

pub const core = struct {
    pub const pubkey = @import("core/pubkey.zig");
    pub const account = @import("core/account.zig");
    pub const transaction = @import("core/transaction.zig");
    pub const hash = @import("core/hash.zig");
    pub const signature = @import("core/signature.zig");
    pub const time = @import("core/time.zig");
    pub const hard_forks = @import("core/hard_forks.zig");
    pub const shred = @import("core/shred.zig");
};

pub const accounts_db = struct {
    pub const db = @import("accountsdb/db.zig");
    pub const bank = @import("accountsdb/bank.zig");
    pub const accounts_file = @import("accountsdb/accounts_file.zig");
    pub const genesis_config = @import("accountsdb/genesis_config.zig");
    pub const index = @import("accountsdb/index.zig");
    pub const snapshots = @import("accountsdb/snapshots.zig");
    pub const sysvars = @import("accountsdb/sysvars.zig");
    pub const download = @import("accountsdb/download.zig");
};

pub const gossip = struct {
    pub const data = @import("gossip/data.zig");
    pub const table = @import("gossip/table.zig");
    pub const service = @import("gossip/service.zig");
    pub const message = @import("gossip/message.zig");
    pub const pull_request = @import("gossip/pull_request.zig");
    pub const pull_response = @import("gossip/pull_response.zig");
    pub const shards = @import("gossip/shards.zig");
    pub const ping_pong = @import("gossip/ping_pong.zig");
    pub const active_set = @import("gossip/active_set.zig");
    pub const dump_service = @import("gossip/dump_service.zig");
};

pub const bloom = struct {
    pub const bit_vec = @import("bloom/bit_vec.zig");
    pub const bit_set = @import("bloom/bit_set.zig");
    pub const bloom = @import("bloom/bloom.zig");
};

pub const version = struct {
    pub const version = @import("version/version.zig");
};

pub const sync = struct {
    pub const backoff = @import("sync/backoff.zig");
    pub const bounded = @import("sync/bounded.zig");
    pub const channel = @import("sync/channel.zig");
    pub const chanx = @import("sync/chanx.zig");
    pub const mpmc = @import("sync/mpmc.zig");
    pub const ref = @import("sync/ref.zig");
    pub const mux = @import("sync/mux.zig");
    pub const once_cell = @import("sync/once_cell.zig");
    pub const parker = @import("sync/parker.zig");
    pub const thread_context = @import("sync/thread_context.zig");
    pub const thread_pool = @import("sync/thread_pool.zig");
    pub const waker = @import("sync/waker.zig");
};

pub const utils = struct {
    pub const shortvec = @import("utils/shortvec.zig");
    pub const types = @import("utils/types.zig");
    pub const varint = @import("utils/varint.zig");
};

pub const trace = struct {
    pub const level = @import("trace/level.zig");
    pub const log = @import("trace/log.zig");
    pub const entry = @import("trace/entry.zig");
};

pub const common = struct {
    pub const lru = @import("common/lru.zig");
    pub const merkle_tree = @import("common/merkle_tree.zig");
};

pub const bincode = struct {
    pub const bincode = @import("bincode/bincode.zig");
};

pub const cmd = struct {
    pub const helpers = @import("cmd/helpers.zig");
};

pub const net = struct {
    pub const net = @import("net/net.zig");
    pub const echo = @import("net/echo.zig");
    pub const packet = @import("net/packet.zig");
    pub const socket_utils = @import("net/socket_utils.zig");
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
