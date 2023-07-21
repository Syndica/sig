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
};

pub const gossip = struct {
    pub usingnamespace @import("gossip/cluster_info.zig");
    pub usingnamespace @import("gossip/cmd.zig");
    pub usingnamespace @import("gossip/crds.zig");
    pub usingnamespace @import("gossip/gossip_service.zig");
    pub usingnamespace @import("gossip/net.zig");
    pub usingnamespace @import("gossip/node.zig");
    pub usingnamespace @import("gossip/packet.zig");
    pub usingnamespace @import("gossip/protocol.zig");
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
};

pub const utils = struct {
    pub usingnamespace @import("utils/shortvec.zig");
    pub usingnamespace @import("utils/varint.zig");
};

pub const trace = struct {
    pub usingnamespace @import("trace/log.zig");
    pub usingnamespace @import("trace/entry.zig");
};
