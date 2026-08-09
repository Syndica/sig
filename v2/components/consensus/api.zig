const replay = @import("replay_api");
const lib = @import("lib");

pub const BlockPool = replay.BlockPool;
pub const BlockRef = replay.BlockRef;

pub const ReplayNotifications = extern struct {
    /// Replay -> consensus.
    ///
    /// Replay writes the root block first, then successfully executed blocks.
    in: lib.ipc.Ring(BlockPool.capacity, BlockRef),

    /// Consensus -> replay.
    ///
    /// Consensus writes finalized blocks here.
    out: lib.ipc.Ring(BlockPool.capacity, BlockRef),

    pub fn init(self: *ReplayNotifications) void {
        self.in.init();
        self.out.init();
    }
};
