const std = @import("std");
const AutoArrayHashMap = std.AutoArrayHashMap;
const AutoHashMap = std.AutoHashMap;
const Account = @import("../core/account.zig").Account;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const Slot = @import("../core/time.zig").Slot;
const Epoch = @import("../core/time.zig").Epoch;
const bincode = @import("../bincode/bincode.zig");

pub const UnixTimestamp = i64;
pub const String = std.ArrayList(u8);
pub const MINIMUM_SLOTS_PER_EPOCH: u64 = 32;

pub const RustDuration = struct {
    secs: u64,
    nanos: u32,
};

pub const PohConfig = struct {
    /// The target tick rate of the cluster.
    target_tick_duration: RustDuration,

    /// The target total tick count to be produced; used for testing only
    target_tick_count: ?u64,

    /// How many hashes to roll before emitting the next tick entry.
    /// None enables "Low power mode", which makes the validator sleep
    /// for `target_tick_duration` instead of hashing
    hashes_per_tick: ?u64,
};

pub const FeeRateGovernor = struct {
    // The current cost of a signature  This amount may increase/decrease over time based on
    // cluster processing load.
    lamports_per_signature: u64 = 0,

    // The target cost of a signature when the cluster is operating around target_signatures_per_slot
    // signatures
    target_lamports_per_signature: u64,

    // Used to estimate the desired processing capacity of the cluster.  As the signatures for
    // recent slots are fewer/greater than this value, lamports_per_signature will decrease/increase
    // for the next slot.  A value of 0 disables lamports_per_signature fee adjustments
    target_signatures_per_slot: u64,

    min_lamports_per_signature: u64,
    max_lamports_per_signature: u64,

    // What portion of collected fees are to be destroyed, as a fraction of std::u8::MAX
    burn_percent: u8,

    pub const @"!bincode-config:lamports_per_signature" = bincode.FieldConfig(u64){ .skip = true };
};

pub const Rent = extern struct {
    /// Rental rate in lamports/byte-year.
    lamports_per_byte_year: u64,

    /// Amount of time (in years) a balance must include rent for the account to
    /// be rent exempt.
    exemption_threshold: f64,

    /// The percentage of collected rent that is burned.
    ///
    /// Valid values are in the range [0, 100]. The remaining percentage is
    /// distributed to validators.
    burn_percent: u8,
};

pub const Inflation = struct {
    /// Initial inflation percentage, from time=0
    initial: f64,

    /// Terminal inflation percentage, to time=INF
    terminal: f64,

    /// Rate per year, at which inflation is lowered until reaching terminal
    ///  i.e. inflation(year) == MAX(terminal, initial*((1-taper)^year))
    taper: f64,

    /// Percentage of total inflation allocated to the foundation
    foundation: f64,
    /// Duration of foundation pool inflation, in years
    foundation_term: f64,

    /// DEPRECATED, this field is currently unused
    __unused: f64,
};

pub const EpochSchedule = extern struct {
    /// The maximum number of slots in each epoch.
    slots_per_epoch: u64,

    /// A number of slots before beginning of an epoch to calculate
    /// a leader schedule for that epoch.
    leader_schedule_slot_offset: u64,

    /// Whether epochs start short and grow.
    warmup: bool,

    /// The first epoch after the warmup period.
    ///
    /// Basically: `log2(slots_per_epoch) - log2(MINIMUM_SLOTS_PER_EPOCH)`.
    first_normal_epoch: Epoch,

    /// The first slot after the warmup period.
    ///
    /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
    first_normal_slot: Slot,

    pub fn getEpoch(self: *const EpochSchedule, slot: Slot) Epoch {
        return self.getEpochAndSlotIndex(slot).epoch;
    }

    pub fn getEpochAndSlotIndex(self: *const EpochSchedule, slot: Slot) struct { epoch: Epoch, slot_index: Slot } {
        if (slot < self.first_normal_slot) {
            var epoch = slot +| MINIMUM_SLOTS_PER_EPOCH +| 1;
            epoch = @ctz(std.math.ceilPowerOfTwo(u64, epoch) catch {
                std.debug.panic("failed to ceil power of two: {d}", .{epoch});
            }) -| @ctz(MINIMUM_SLOTS_PER_EPOCH) -| 1;

            const exponent = epoch +| @ctz(MINIMUM_SLOTS_PER_EPOCH);
            const epoch_len = std.math.powi(u64, 2, exponent) catch std.math.maxInt(u64);

            const slot_index = slot -| (epoch_len -| MINIMUM_SLOTS_PER_EPOCH);

            return .{
                .epoch = epoch,
                .slot_index = slot_index,
            };
        } else {
            const normal_slot_index = slot -| self.first_normal_slot;
            const normal_epoch_index = std.math.divTrunc(u64, normal_slot_index, self.slots_per_epoch) catch 0;

            const epoch = self.first_normal_epoch +| normal_epoch_index;
            const slot_index = std.math.rem(u64, normal_slot_index, self.slots_per_epoch) catch 0;

            return .{
                .epoch = epoch,
                .slot_index = slot_index,
            };
        }
    }
};

pub const ClusterType = enum(u8) {
    Testnet,
    MainnetBeta,
    Devnet,
    Development,
};

pub const GenesisConfig = struct {
    // when the network (bootstrap validator) was started relative to the UNIX Epoch
    creation_time: UnixTimestamp,
    // initial accounts
    accounts: AutoHashMap(Pubkey, Account),
    // /// built-in programs
    native_instruction_processors: std.ArrayList(struct { String, Pubkey }),
    /// accounts for network rewards, these do not count towards capitalization
    rewards_pools: AutoHashMap(Pubkey, Account),
    ticks_per_slot: u64,
    unused: u64,
    /// network speed configuration
    poh_config: PohConfig,
    /// this field exists only to ensure that the binary layout of GenesisConfig remains compatible
    /// with the Solana v0.23 release line
    __backwards_compat_with_v0_23: u64,
    /// transaction fee config
    fee_rate_governor: FeeRateGovernor,
    /// rent config
    rent: Rent,
    /// inflation config
    inflation: Inflation,
    /// how slots map to epochs
    epoch_schedule: EpochSchedule,
    /// network runlevel
    cluster_type: ClusterType,

    pub fn init(
        allocator: std.mem.Allocator,
        genesis_path: []const u8,
    ) !GenesisConfig {
        var file = try std.fs.cwd().openFile(genesis_path, .{});
        defer file.close();
        const config = try bincode.read(allocator, GenesisConfig, file.reader(), .{});

        return config;
    }

    pub fn deinit(self: GenesisConfig, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
        // bincode.free(allocator, self);
    }
};

test "core.genesis_config: deserialize config" {
    const allocator = std.testing.allocator;

    const genesis_path = "./test_data/genesis.bin";
    const config = try GenesisConfig.init(allocator, genesis_path);
    defer config.deinit(allocator);

    try std.testing.expect(config.cluster_type == ClusterType.Development);
}
