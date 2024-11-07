const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const Allocator = std.mem.Allocator;

const BlockstoreReader = sig.ledger.BlockstoreReader;

const GetTransaction = rpc.methods.GetTransaction;

pub const RpcService = struct {
    blockstore: BlockstoreReader,

    const Self = @This();

    pub fn getTransaction(self: Self, request: GetTransaction) ?GetTransaction.Response {
        _ = self; // autofix
        _ = request; // autofix
        // self.blockstore.getCompleteTransaction(signature: Signature, highest_confirmed_slot: Slot)
        return undefined;
    }
};
