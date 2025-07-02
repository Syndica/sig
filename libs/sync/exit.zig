const std = @import("std");
const Atomic = std.atomic.Value;

pub const ExitCondition = union(enum) {
    unordered: *Atomic(bool),
    ordered: struct {
        exit_counter: *Atomic(u64),
        exit_index: u64,
    },

    pub fn setExit(self: ExitCondition) void {
        switch (self) {
            .unordered => |e| e.store(true, .release),
            .ordered => |e| e.exit_counter.store(e.exit_index + 1, .release),
        }
    }

    pub fn shouldRun(self: ExitCondition) bool {
        return !self.shouldExit();
    }

    pub fn shouldExit(self: ExitCondition) bool {
        switch (self) {
            .unordered => |e| return e.load(.acquire),
            .ordered => |e| return e.exit_counter.load(.acquire) >= e.exit_index,
        }
    }

    pub fn afterExit(self: ExitCondition) void {
        switch (self) {
            .unordered => {},
            // continue the exit process by incrementing the exit_counter
            .ordered => |e| e.exit_counter.store(e.exit_index + 1, .release),
        }
    }
};
