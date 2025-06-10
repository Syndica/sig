//! Implements a basic ProgramCache. Currently designed to meet consensus, and not much more.

const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

const HashMap = std.AutoArrayHashMapUnmanaged;
const ArrayList = std.ArrayListUnmanaged;

const RwMux = sig.sync.RwMux;

const ProgramRuntimeEnv = struct {};

/// Verified program
const Executable = sig.vm.Executable;
const BuiltinProgram = struct {};

// TODO: data types from consensus?
const ForkId = struct {};
// TODO: data types from consensus?
const ForkGraph = struct {
    /// is the deployed program visible & available to our current slot+fork?
    fn isProgramAvailable(
        self: *const ForkGraph,
        program_deployed_slot: Slot,
        program_deployed_fork: ForkId,
        current_slot: Slot,
        current_fork: ForkId,
    ) bool {
        _ = self;
        _ = program_deployed_slot;
        _ = program_deployed_fork;
        _ = current_slot;
        _ = current_fork;
        @panic("TODO");
    }

    /// for pruning entries
    fn isForkOrphaned(self: *const ForkGraph, fork: ForkId) bool {
        _ = self;
        _ = fork;
        @panic("TODO");
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L622
/// effectively a global, "fork graph aware"
pub const ProgramCache = struct {
    index: Index = .{},

    last_rerooting: struct { Slot, Epoch },

    current_environment: ProgramRuntimeEnv,
    next_environmment: ?ProgramRuntimeEnv,

    fork_graph: *const ForkGraph,

    /// [agave] https://github.com/anza-xyz/agave/blob/452f4600842159e099a84bf18cca19408da103c9/program-runtime/src/loaded_programs.rs#L180
    /// "Holds a program version at a specific address and on a specific slot / fork.""
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
            /// Tombstone for programs which currently do not pass the verifier but could if the feature set changed.
            failed_verification_with: ProgramRuntimeEnv,
            /// Tombstone for programs that were either explicitly closed or never deployed.
            ///
            /// It's also used for accounts belonging to program loaders, that don't actually contain program code (e.g. buffer accounts for LoaderV3 programs).
            closed,
            /// Tombstone for programs which have recently been modified but the new version is not visible yet.
            delay_visibility,
            /// Successfully verified but not currently compiled.
            ///
            /// It continues to track usage statistics even when the compiled executable of the program is evicted from memory.
            unloaded: ProgramRuntimeEnv,
            /// Verified and compiled program
            loaded: Executable,
            /// A built-in program which is not stored on-chain but backed into and distributed with the validator
            builtin: BuiltinProgram,
        };

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
        const partition_point = std.sort.partitionPoint(Entry, versions.items, entry, Entry.partition);
        if (Entry.compare(entry, versions.items[partition_point]) == .eq) {
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

        const partition_point = std.sort.partitionPoint(Entry, versions.items, entry, Entry.partition);

        if (Entry.compare(entry, versions.items[partition_point]) == .eq) {
            // replace entry
            const existing_entry = &versions.items[partition_point];

            const is_valid_entry_replacement =
                (existing_entry.program == .builtin and entry.program == .builtin) or
                (existing_entry.program == .unloaded and entry.program == .loaded);

            // TODO: agave logs here instead of panicking. Not sure why this would ever happen?
            if (!is_valid_entry_replacement) @panic("invalid entry replacement");

            existing_entry.* = entry;
        } else {
            // insert entry
            try versions.insert(allocator, partition_point, entry);
        }
    }

    pub fn getEnvironmentForEpoch(self: *const ProgramCache, epoch: Epoch) ProgramRuntimeEnv {
        if (epoch == self.last_rerooting.@"1") return self.current_environment;
        return self.next_environmment orelse self.current_environment;
    }
};

// TODO: remove this
test {
    var skip_test: bool = true;
    _ = &skip_test;
    if (skip_test) return error.SkipZigTest;

    var cache: ProgramCache = .{
        .fork_graph = undefined,
        .current_environment = .{},
        .next_environmment = .{},
        .last_rerooting = .{ 0, 0 },
    };
    _ = try cache.insertEntry(
        std.testing.allocator,
        Pubkey.ZEROES,
        ProgramCache.Entry.DEFAULT,
    );
}
