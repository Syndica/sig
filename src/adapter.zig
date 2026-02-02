const std = @import("std");
const sig = @import("sig.zig");

/// Links dependencies with dependents. Connects components from distant regions of the code.
pub const EpochContextManager = struct {
    schedule: sig.core.EpochSchedule,
    contexts: ContextWindow,

    const ContextWindow = sig.sync.SharedPointerWindow(
        sig.core.EpochContext,
        sig.core.EpochContext.deinit,
        std.mem.Allocator,
    );

    /// all contexts that are `put` into this context manager must be
    /// allocated using the same allocator passed here.
    pub fn init(
        allocator: std.mem.Allocator,
        schedule: sig.core.EpochSchedule,
    ) std.mem.Allocator.Error!EpochContextManager {
        return .{
            .schedule = schedule,
            .contexts = try .init(allocator, 3, 0, allocator),
        };
    }

    pub fn deinit(self: EpochContextManager) void {
        self.contexts.deinit();
    }

    pub fn put(
        self: *EpochContextManager,
        epoch: sig.core.Epoch,
        context: sig.core.EpochContext,
    ) !void {
        try self.contexts.put(epoch, context);
    }

    /// call `release` when done with pointer
    pub fn get(self: *EpochContextManager, epoch: sig.core.Epoch) ?*const sig.core.EpochContext {
        return self.contexts.get(@intCast(epoch));
    }

    pub fn contains(self: *EpochContextManager, epoch: sig.core.Epoch) bool {
        return self.contexts.contains(@intCast(epoch));
    }

    pub fn setEpoch(self: *EpochContextManager, epoch: sig.core.Epoch) !void {
        try self.contexts.realign(@intCast(epoch));
    }

    pub fn setSlot(self: *EpochContextManager, slot: sig.core.Slot) !void {
        try self.contexts.realign(@intCast(self.schedule.getEpoch(slot)));
    }

    pub fn release(self: *EpochContextManager, context: *const sig.core.EpochContext) void {
        self.contexts.release(context);
    }

    pub fn getLeader(self: *EpochContextManager, slot: sig.core.Slot) ?sig.core.Pubkey {
        const epoch, const slot_index = self.schedule.getEpochAndSlotIndex(slot);
        const context = self.contexts.get(epoch) orelse return null;
        defer self.contexts.release(context);
        return context.leader_schedule[slot_index];
    }

    pub fn slotLeaders(self: *EpochContextManager) sig.core.leader_schedule.SlotLeaders {
        return .init(self, getLeader);
    }
};

pub const RpcEpochContextService = struct {
    logger: Logger,
    rpc_client: sig.rpc.Client,
    state: *EpochContextManager,

    const Logger = sig.trace.Logger(@typeName(RpcEpochContextService));

    pub fn init(
        logger: Logger,
        state: *EpochContextManager,
        rpc_client: sig.rpc.Client,
    ) RpcEpochContextService {
        return .{
            .logger = .from(logger),
            .rpc_client = rpc_client,
            .state = state,
        };
    }

    pub fn deinit(self: *RpcEpochContextService) void {
        self.rpc_client.deinit();
    }

    pub fn run(
        self: *RpcEpochContextService,
        gpa: std.mem.Allocator,
        exit: *std.atomic.Value(bool),
    ) void {
        var i: usize = 0;
        while (!exit.load(.monotonic)) {
            if (i % 1000 == 0) {
                var result: anyerror!void = undefined;
                for (0..3) |_| {
                    result = self.refresh(gpa);
                    if (result != error.EndOfStream) break;
                }
                result catch |e|
                    self.logger.err().logf("failed to refresh epoch context via rpc: {}", .{e});
            }
            std.Thread.sleep(100 * std.time.ns_per_ms);
            i += 1;
        }
    }

    fn refresh(self: *RpcEpochContextService, gpa: std.mem.Allocator) !void {
        const response = try self.rpc_client.getSlot(.{});
        defer response.deinit();
        const this_slot = try response.result();
        const this_epoch = self.state.schedule.getEpoch(this_slot);
        const old_slot = this_slot -| self.state.schedule.slots_per_epoch;

        try self.state.setEpoch(this_epoch);

        const actual_old_slot_epoch = self.state.schedule.getEpoch(old_slot);
        if (this_epoch -| 1 != actual_old_slot_epoch) {
            std.debug.panic("{} != {}", .{ this_epoch -| 1, actual_old_slot_epoch });
        }
        if (self.state.contains(this_epoch)) return;

        if (self.getLeaderSchedule(gpa, old_slot)) |ls2| {
            const ctx2: sig.core.EpochContext = .{
                .staked_nodes = .empty,
                .leader_schedule = ls2,
            };
            errdefer gpa.free(ls2);
            try self.state.put(this_epoch, ctx2);
        } else |e| if (this_epoch == this_epoch) {
            return e;
        }
    }

    fn getLeaderSchedule(
        self: *RpcEpochContextService,
        gpa: std.mem.Allocator,
        slot: sig.core.Slot,
    ) ![]const sig.core.Pubkey {
        const response = try self.rpc_client.getLeaderSchedule(.{ .slot = slot });
        defer response.deinit();
        const rpc_schedule = (try response.result()).value;
        const schedule: sig.core.leader_schedule.LeaderSchedule = try .fromMap(gpa, rpc_schedule);
        return schedule.slot_leaders;
    }
};

test RpcEpochContextService {
    const gpa = std.testing.allocator;

    var epoch_context_manager: EpochContextManager = try .init(gpa, .INIT);
    defer epoch_context_manager.deinit();

    var rpc_epoch_ctx_service: RpcEpochContextService = init: {
        var rpc_client: sig.rpc.Client = try .init(gpa, .Testnet, .{});
        errdefer rpc_client.deinit();
        break :init .init(.noop, &epoch_context_manager, rpc_client);
    };
    defer rpc_epoch_ctx_service.deinit();
    try rpc_epoch_ctx_service.refresh(gpa);
}
