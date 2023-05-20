pub const rpc = struct {
    usingnamespace @import("./rpc/client.zig");
    const types = struct {
        usingnamespace @import("./rpc/types.zig");
    };
};

pub const core = struct {
    usingnamespace @import("./core/pubkey.zig");
    usingnamespace @import("./core/account.zig");
    usingnamespace @import("./core/transaction.zig");
};
