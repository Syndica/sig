pub const fork_choice = @import("fork_choice.zig");
pub const progress_map = @import("progress_map.zig");

comptime {
    _ = fork_choice;
    _ = progress_map;
}

pub const HeaviestSubtreeForkChoice = fork_choice.ForkChoice;
pub const ForkWeight = fork_choice.ForkWeight;
pub const ForkInfo = fork_choice.ForkInfo;

pub const ProgressMap = progress_map.ProgressMap;
