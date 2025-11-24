//! Links dependencies with dependents. Connects components from distant regions of the code.

const std = @import("std");
const sig = @import("sig.zig");

const leader_schedule = sig.core.leader_schedule;
const rpc = sig.rpc;

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const EpochContext = sig.core.EpochContext;
const EpochSchedule = sig.core.EpochSchedule;
const Slot = sig.core.Slot;

pub const EpochContextManager = struct {
    schedule: sig.core.EpochSchedule,
    contexts: ContextWindow,

    const ContextWindow = sig.sync.SharedPointerWindow(
        sig.core.EpochContext,
        sig.core.EpochContext.deinit,
        std.mem.Allocator,
    );

    const Self = @This();

    /// all contexts that are `put` into this context manager must be
    /// allocated using the same allocator passed here.
    pub fn init(allocator: Allocator, schedule: EpochSchedule) Allocator.Error!Self {
        return .{
            .schedule = schedule,
            .contexts = try ContextWindow.init(allocator, 3, 0, allocator),
        };
    }

    pub fn deinit(self: Self) void {
        self.contexts.deinit();
    }

    pub fn put(self: *Self, epoch: Epoch, context: sig.core.EpochContext) !void {
        try self.contexts.put(epoch, context);
    }

    /// call `release` when done with pointer
    pub fn get(self: *Self, epoch: Epoch) ?*const sig.core.EpochContext {
        return self.contexts.get(@intCast(epoch));
    }

    pub fn contains(self: *Self, epoch: Epoch) bool {
        return self.contexts.contains(@intCast(epoch));
    }

    pub fn setEpoch(self: *Self, epoch: Epoch) !void {
        try self.contexts.realign(@intCast(epoch));
    }

    pub fn setSlot(self: *Self, slot: Slot) !void {
        try self.contexts.realign(@intCast(self.schedule.getEpoch(slot)));
    }

    pub fn release(self: *Self, context: *const sig.core.EpochContext) void {
        self.contexts.release(context);
    }

    pub fn getLeader(self: *Self, slot: Slot) ?sig.core.Pubkey {
        const epoch, const slot_index = self.schedule.getEpochAndSlotIndex(slot);
        const context = self.contexts.get(epoch) orelse return null;
        defer self.contexts.release(context);
        return context.leader_schedule[slot_index];
    }

    pub fn slotLeaders(self: *Self) sig.core.leader_schedule.SlotLeaders {
        return sig.core.leader_schedule.SlotLeaders.init(self, getLeader);
    }
};

pub const RpcEpochContextService = struct {
    allocator: std.mem.Allocator,
    logger: Logger,
    rpc_client: rpc.Client,
    state: *EpochContextManager,
    magic_tracker: *sig.core.magic_info.MagicTracker,

    const Self = @This();
    const Logger = sig.trace.Logger(@typeName(Self));

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        state: *EpochContextManager,
        magic_tracker: *sig.core.magic_info.MagicTracker,
        rpc_client: rpc.Client,
    ) Self {
        return .{
            .allocator = allocator,
            .logger = logger.withScope(@typeName(Self)),
            .rpc_client = rpc_client,
            .state = state,
            .magic_tracker = magic_tracker,
        };
    }

    pub fn run(self: *Self, exit: *std.atomic.Value(bool)) void {
        var i: usize = 0;
        while (!exit.load(.monotonic)) {
            if (i % 1000 == 0) {
                var result: anyerror!void = undefined;
                for (0..3) |_| {
                    result = self.refresh();
                    if (result != error.EndOfStream) break;
                }
                result catch |e|
                    self.logger.err().logf("failed to refresh epoch context via rpc: {}", .{e});
            }
            std.Thread.sleep(std.time.ns_per_s);
            i += 1;
        }
    }

    fn refresh(self: *Self) !void {
        const response = try self.rpc_client.getSlot(.{});
        defer response.deinit();
        const slot = try response.result();

        // Get the current epoch, and the epoch whose stakes were used to compute the leader schedule
        // for the current epoch.
        const epoch = self.state.schedule.getEpoch(slot);
        const leader_schedule_epoch = self.magic_tracker.epoch_schedule.getEpoch(
            slot -| self.magic_tracker.epoch_schedule.leader_schedule_slot_offset,
        );

        // Iterate from the leader schedule epoch to the current epoch, and populate any missing epochs in the magic tracker.
        for (leader_schedule_epoch..epoch + 1) |e| {
            if (self.magic_tracker.rooted_epochs.isNext(e)) {
                const first_slot_in_epoch = self.magic_tracker.epoch_schedule.getFirstSlotInEpoch(e);
                const epoch_leaders = try self.getLeaderSchedule(
                    first_slot_in_epoch +|
                        self.magic_tracker.epoch_schedule.leader_schedule_slot_offset,
                );

                var entry = try self.allocator.create(sig.core.magic_info.EpochInfo);
                entry.* = .{
                    .leaders = .{
                        .leaders = epoch_leaders,
                        .start = self.magic_tracker.epoch_schedule.getFirstSlotInEpoch(e),
                        .end = self.magic_tracker.epoch_schedule.getLastSlotInEpoch(e),
                    },
                    .stakes = .EMPTY,
                };
                entry.stakes.stakes.epoch = e;
                errdefer {
                    entry.deinit(self.allocator);
                    self.allocator.destroy(entry);
                }

                try self.magic_tracker.rooted_epochs.insert(self.allocator, entry);
            }
        }

        const this_slot = try response.result();
        const this_epoch = self.state.schedule.getEpoch(this_slot);
        const old_slot = this_slot -| self.state.schedule.slots_per_epoch;

        try self.state.setEpoch(this_epoch);

        for (0..3) |epoch_offset| {
            const selected_slot = old_slot + epoch_offset * self.state.schedule.slots_per_epoch;
            const selected_epoch = this_epoch + epoch_offset -| 1;
            std.debug.assert(selected_epoch == self.state.schedule.getEpoch(selected_slot));

            if (self.state.contains(selected_epoch)) {
                continue;
            }

            if (self.getLeaderSchedule(selected_slot)) |ls2| {
                const ctx2 = EpochContext{ .staked_nodes = .{}, .leader_schedule = ls2 };
                errdefer self.allocator.free(ls2);
                try self.state.put(selected_epoch, ctx2);
            } else |e| if (selected_epoch == this_epoch) {
                return e;
            }
        }
    }

    fn getLeaderSchedule(self: *Self, slot: sig.core.Slot) ![]const sig.core.Pubkey {
        const response = try self.rpc_client.getLeaderSchedule(.{ .slot = slot });
        defer response.deinit();
        const rpc_schedule = (try response.result()).value;
        const schedule = try leader_schedule.LeaderSchedule.fromMap(self.allocator, rpc_schedule);
        return schedule.slot_leaders;
    }
};

test "epochctx" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    const genesis_config = try sig.core.GenesisConfig
        .init(allocator, "data/genesis-files/testnet_genesis.bin");
    defer genesis_config.deinit(allocator);

    var rpc_client = rpc.Client.init(allocator, .Testnet, .{});
    defer rpc_client.deinit();

    var epoch_context_manager = try sig.adapter.EpochContextManager
        .init(allocator, genesis_config.epoch_schedule);
    defer epoch_context_manager.deinit();
    var rpc_epoch_ctx_service = sig.adapter.RpcEpochContextService
        .init(allocator, .noop, &epoch_context_manager, rpc_client);

    try rpc_epoch_ctx_service.refresh();
}
