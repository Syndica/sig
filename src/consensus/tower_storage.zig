const sig = @import("../sig.zig");
const Pubkey = sig.core.Pubkey;
const Tower = sig.consensus.tower.Tower;

pub const SavedTower = struct {
    pub fn init(
        tower: *const Tower,
        keypair: anytype,
    ) !SavedTower {
        _ = tower;
        _ = keypair;
        @panic("Unimplemented");
    }
};

pub const SavedTower1_7_14 = struct {};

pub const SavedTowerVersions = union(enum) { current: SavedTower, v1_17_14: SavedTower1_7_14 };

pub const TowerStorage = struct {
    pub fn load(self: *const TowerStorage, node_pubkey: *const Pubkey) !Tower {
        _ = self;
        _ = node_pubkey;
        @panic("Unimplemented");
    }
    pub fn store(self: *const TowerStorage, saved_tower: *const SavedTowerVersions) !void {
        _ = self;
        _ = saved_tower;
        @panic("Unimplemented");
    }
};
