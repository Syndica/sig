//! Implements a basic ProgramCache. Currently designed to meet consensus, and not much more.
const std = @import("std");
const sig = @import("../sig.zig");

const BuiltinProgram = sig.vm.BuiltinProgram;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const HashMap = std.AutoArrayHashMapUnmanaged;
const ArrayList = std.ArrayListUnmanaged;

// NOTE: SIMD-0177 (unmerged as of June 2025) introduces ABI v2. Ignoring this for now.
const ProgramRuntimeEnvironment = struct {
    config: sig.vm.Config = .{},
    syscall_registry: sig.vm.Registry(sig.vm.syscalls.Syscall) = .{},
};

/// A verified program
// NOTE: caching this seems a bit useless? We save on ELF parsing; Agave caches JIT code.
const Executable = sig.vm.Executable;

const ForkGraph = struct {
    // TODO: need to plug in some data from replay for this.
    // sig.replay.trackers.SlotTracker is the closest type I know of
    // We will need the fork graph for the agave methods:
    //     - finish_cooperative_loading_task (called by replenish_program_cache to make a ProgramCacheForTxBatch - not needed now)
    //     - prune (removes unnecessary entries before rerooting - not needed now)
    //     - extract (seems only needed for ProgramCacheForTxBatch stuff - not needed now)

    // NOTE: forks on Solana are about block inclusion - i.e. which slots are occupied. This means
    // that we can distinguish forks using slot numbers.

    // we could reimplement ForkGraph::relationship, but I think we only need two know about these two cases.

    /// is the deployed program visible & available to our current slot+fork?
    fn isProgramAvailable(
        self: *const ForkGraph,
        program_deployed_slot: Slot,
        current_slot: Slot,
    ) bool {
        _ = self;
        _ = program_deployed_slot;
        _ = current_slot;
        @panic("TODO");
    }

    /// for pruning entries
    fn isForkOrphaned(self: *const ForkGraph, fork: Slot) bool {
        _ = self;
        _ = fork;
        @panic("TODO");
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L32
const DELAY_VISIBILITY_SLOT_OFFSET = 1;

/// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L622
/// effectively a global, and "fork graph aware"
pub const ProgramCache = struct {
    index: Index = .{},

    last_rerooting: struct { Slot, Epoch },

    // thought: does it make sense for these to live in here?
    current_environment: ProgramRuntimeEnvironment,
    next_environmment: ?ProgramRuntimeEnvironment, // for epoch transitions

    fork_graph: *const ForkGraph = &.{},

    /// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L180
    /// "Holds a program version at a specific address and on a specific slot / fork.""
    // pretty much 1:1 with Agave's ProgramCacheEntry, except we don't have atomic counters for
    // stats/eviction, and Type has been simplified.
    const Entry = struct {
        program: Type,

        owner: Owner,
        program_account_size: usize,
        /// Slot in which the program was deployed
        deployment_slot: Slot,
        /// Slot in which this entry will become active (can be in the future)
        effective_slot: Slot,

        const DEFAULT: Entry = .{
            .program = .closed,
            .owner = .native_loader,
            .program_account_size = 0,
            .deployment_slot = 0,
            .effective_slot = 0,
        };

        /// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L57
        const Owner = enum { native_loader, loader_v1, loader_v2, loader_v3, loader_v4 };

        /// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L127
        const Type = union(enum) {
            /// Did not pass the verifier, but could potentially work next epoch.
            failed_verification,
            /// Tombstone for programs that were either explicitly closed or never deployed.
            ///
            /// It's also used for accounts belonging to program loaders, that don't actually contain program code (e.g. buffer accounts for LoaderV3 programs).
            closed,
            /// Tombstone for programs which have recently been modified but the new version is not visible yet.
            delay_visibility,
            /// Verified and compiled program
            loaded: Executable,

            // unloaded field seems unnecessary: "verified but not currently compiled"
            // I don't think we need the builtin field, at least for now
        };

        fn newTombstone(slot: Slot, owner: Owner, reason: Type) Entry {
            return Entry{
                .program = reason,
                .owner = owner,
                .program_account_size = 0,
                .effective_slot = slot,
                .deployment_slot = slot,
            };
        }

        fn isImplicitDelayVisibilityTombstone(self: Entry, slot: Slot) bool {
            if (slot < self.deployment_slot) return false;
            if (slot >= self.effective_slot) return false;
            return self.effective_slot -| self.deployment_slot == DELAY_VISIBILITY_SLOT_OFFSET;
        }

        fn compare(context: Entry, item: Entry) std.math.Order {
            return switch (std.math.order(context.effective_slot, item.effective_slot)) {
                .gt, .lt => |order| order,
                .eq => std.math.order(context.deployment_slot, item.deployment_slot),
            };
        }

        fn partition(context: Entry, item: Entry) bool {
            return compare(context, item) == .gt;
        }
    };

    const Index = struct {
        // TODO: this will badly need pruning!
        // agave uses Arc<Entry>, not entirely convinced we need that.
        entries: HashMap(Pubkey, ArrayList(Entry)) = .{},

        /// Programs currently being loaded.
        /// program key -> slot in which it is being loaded
        loading_entries: sig.sync.Mux(HashMap(Pubkey, Slot)) = .init(.{}),
    };

    pub fn deinit(self: *ProgramCache, allocator: std.mem.Allocator) void {
        for (self.index.entries.values()) |*entry_list| entry_list.deinit(allocator);
        self.index.entries.deinit(allocator);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L740
    /// Replaces any existing entries, if any.
    // NOTE: why does agave call this "replenish"?
    // NOTE: agave implements this on top of ProgramCacheForTxBatch. Skipping ForTxBatch for now,
    // seems to be purely an optimisation.
    pub fn insertEntryUnchecked(
        self: *ProgramCache,
        allocator: std.mem.Allocator,
        key: Pubkey,
        entry: Entry,
    ) error{OutOfMemory}!void {
        const versions = (try (self.index.entries.getOrPutValue(allocator, key, .{}))).value_ptr;
        const partition_point = std.sort.partitionPoint(
            Entry,
            versions.items,
            entry,
            Entry.partition,
        );
        if (versions.items.len > 0 and Entry.compare(
            entry,
            versions.items[partition_point],
        ) == .eq) {
            // replace entry
            versions.items[partition_point] = entry;
        } else {
            // insert entry
            try versions.insert(allocator, partition_point, entry);
        }
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L854
    // NOTE: why does agave call this "assign_program"?
    pub fn insertEntry(
        self: *ProgramCache,
        allocator: std.mem.Allocator,
        key: Pubkey,
        entry: Entry,
    ) error{OutOfMemory}!void {
        if (entry.program == .delay_visibility) unreachable;

        const versions = (try (self.index.entries.getOrPutValue(allocator, key, .{}))).value_ptr;

        const partition_point = std.sort.partitionPoint(
            Entry,
            versions.items,
            entry,
            Entry.partition,
        );

        if (versions.items.len > 0 and Entry.compare(
            entry,
            versions.items[partition_point],
        ) == .eq) {
            // entry replacement is only valid if the new entry is loaded and the existing is
            // unloaded (or both are builtins).
            // We do not have either of these kinds, so entry replacement is always invalid.

            // TODO: agave logs here instead of panicking. Not sure why this would ever happen?
            @panic("invalid entry replacement");
        } else {
            // insert entry
            try versions.insert(allocator, partition_point, entry);
        }
    }

    pub fn getEnvironmentForEpoch(
        self: *const ProgramCache,
        epoch: Epoch,
    ) ProgramRuntimeEnvironment {
        if (epoch == self.last_rerooting.@"1") return self.current_environment;
        return self.next_environmment orelse self.current_environment;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L760
    pub fn find(
        self: *const ProgramCache,
        key: Pubkey,
        slot: Slot,
    ) ?Entry {
        // NOTE: the agave version of this function is implemented on `ProgramCacheForTxBatch`.
        // As far as I can tell right now, this (and its modified_entries) field is just an
        // optimisation and isn't needed for consensus.
        const entries = self.index.entries.get(key) orelse return null;

        const latest_entry = entries.items[entries.items.len - 1];

        // why convert implicit tombstones into explicit ones? Feels weird.
        return if (latest_entry.isImplicitDelayVisibilityTombstone(slot)) blk: {
            break :blk Entry.newTombstone(
                latest_entry.deployment_slot,
                latest_entry.owner,
                .delay_visibility,
            );
        } else latest_entry;
    }
};

test "program cache basic usage" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var cache: ProgramCache = .{
        .fork_graph = undefined,
        .current_environment = .{},
        .next_environmment = .{},
        .last_rerooting = .{ 0, 0 },
    };
    defer cache.deinit(allocator);

    const loaded_entry: ProgramCache.Entry = .{
        .deployment_slot = 0,
        .effective_slot = 1,
        .owner = .loader_v1,
        .program = .{ .loaded = undefined },
        .program_account_size = 100,
    };

    const k1 = Pubkey.initRandom(prng.random());
    try cache.insertEntryUnchecked(allocator, k1, loaded_entry);

    const replacement_entry: ProgramCache.Entry = .{
        .deployment_slot = 2,
        .effective_slot = 3,
        .owner = .loader_v1,
        .program = .{ .loaded = undefined },
        .program_account_size = 100,
    };

    const k2 = Pubkey.initRandom(prng.random());
    try cache.insertEntry(allocator, k2, replacement_entry);

    {
        const entry = cache.find(k1, 0) orelse @panic("missing");
        try std.testing.expect(entry.program == .delay_visibility);
        try std.testing.expect(!entry.isImplicitDelayVisibilityTombstone(0));
    }

    {
        const entry = cache.find(k2, 3) orelse @panic("missing");
        try std.testing.expect(entry.program == .loaded);
        try std.testing.expect(entry.isImplicitDelayVisibilityTombstone(2));
    }

    try std.testing.expectEqual(ProgramRuntimeEnvironment{}, cache.getEnvironmentForEpoch(0));
}
