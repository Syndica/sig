pub const rpc = struct {
    pub usingnamespace @import("rpc/client.zig");
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
    pub usingnamespace @import("core/slot.zig");
    pub usingnamespace @import("core/hard_forks.zig");
    pub usingnamespace @import("core/shred.zig");
};

pub const gossip = struct {
    pub usingnamespace @import("gossip/crds.zig");
    pub usingnamespace @import("gossip/crds_table.zig");
    pub usingnamespace @import("gossip/gossip_service.zig");
    pub usingnamespace @import("gossip/node.zig");
    pub usingnamespace @import("gossip/packet.zig");
    pub usingnamespace @import("gossip/protocol.zig");
    pub usingnamespace @import("gossip/pull_request.zig");
    pub usingnamespace @import("gossip/pull_response.zig");
    pub usingnamespace @import("gossip/crds_shards.zig");
    pub usingnamespace @import("gossip/ping_pong.zig");
    pub usingnamespace @import("gossip/active_set.zig");
    pub usingnamespace @import("gossip/socket_utils.zig");
};

pub const bloom = struct {
    pub usingnamespace @import("bloom/bitvec.zig");
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
};

pub const utils = struct {
    pub usingnamespace @import("utils/shortvec.zig");
    pub usingnamespace @import("utils/varint.zig");
};

pub const trace = struct {
    pub usingnamespace @import("trace/log.zig");
    pub usingnamespace @import("trace/entry.zig");
};

pub const common = struct {
    pub usingnamespace @import("common/lru.zig");
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
};
