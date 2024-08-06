//! genesis config fields

const std = @import("std");
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

/// Analogous to [PohConfig](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/poh_config.rs#L10)
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

/// Analogous to [FeeRateGovernor](https://github.com/anza-xyz/agave/blob/ec9bd798492c3b15d62942f2d9b5923b99042350/sdk/program/src/fee_calculator.rs#L55)
pub const FeeRateGovernor = struct {
    /// The current cost of a signature  This amount may increase/decrease over time based on
    /// cluster processing load.
    lamports_per_signature: u64 = 0,

    /// The target cost of a signature when the cluster is operating around target_signatures_per_slot
    /// signatures.
    target_lamports_per_signature: u64,

    /// Used to estimate the desired processing capacity of the cluster.  As the signatures for
    /// recent slots are fewer/greater than this value, lamports_per_signature will decrease/increase
    /// for the next slot.  A value of 0 disables lamports_per_signature fee adjustments.
    target_signatures_per_slot: u64,

    min_lamports_per_signature: u64,
    max_lamports_per_signature: u64,

    /// What portion of collected fees are to be destroyed, as a fraction of std::u8::MAX.
    burn_percent: u8,

    pub const @"!bincode-config:lamports_per_signature" = bincode.FieldConfig(u64){ .skip = true };

    pub fn random(rand: std.Random) FeeRateGovernor {
        return .{
            .lamports_per_signature = rand.int(u64),
            .target_lamports_per_signature = rand.int(u64),
            .target_signatures_per_slot = rand.int(u64),
            .min_lamports_per_signature = rand.int(u64),
            .max_lamports_per_signature = rand.int(u64),
            .burn_percent = rand.uintAtMost(u8, 100),
        };
    }
};

/// Analogous to [Rent](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/rent.rs#L13)
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

    pub fn random(rand: std.Random) Rent {
        return .{
            .lamports_per_byte_year = rand.int(u64),
            .exemption_threshold = @bitCast(rand.int(u64)),
            .burn_percent = rand.uintAtMost(u8, 100),
        };
    }
};

/// Analogous to [Inflation](https://github.com/anza-xyz/agave/blob/55aff7288e596e93d1184ba827048b1e3dc98061/sdk/src/inflation.rs#L6)
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

    pub fn random(rand: std.Random) Inflation {
        return .{
            .initial = @bitCast(rand.int(u64)),
            .terminal = @bitCast(rand.int(u64)),
            .taper = @bitCast(rand.int(u64)),
            .foundation = @bitCast(rand.int(u64)),
            .foundation_term = @bitCast(rand.int(u64)),
            .__unused = @bitCast(rand.int(u64)),
        };
    }
};

/// Analogous to [EpochSchedule](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/epoch_schedule.rs#L35)
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
        return self.getEpochAndSlotIndex(slot)[0];
    }

    pub fn getEpochAndSlotIndex(self: *const EpochSchedule, slot: Slot) struct { Epoch, Slot } {
        if (slot < self.first_normal_slot) {
            var epoch = slot +| MINIMUM_SLOTS_PER_EPOCH +| 1;
            epoch = @ctz(std.math.ceilPowerOfTwo(u64, epoch) catch {
                std.debug.panic("failed to ceil power of two: {d}", .{epoch});
            }) -| @ctz(MINIMUM_SLOTS_PER_EPOCH) -| 1;

            const exponent = epoch +| @ctz(MINIMUM_SLOTS_PER_EPOCH);
            const epoch_len = std.math.powi(u64, 2, exponent) catch std.math.maxInt(u64);

            const slot_index = slot -| (epoch_len -| MINIMUM_SLOTS_PER_EPOCH);

            return .{ epoch, slot_index };
        } else {
            const normal_slot_index = slot -| self.first_normal_slot;
            const normal_epoch_index = std.math.divTrunc(u64, normal_slot_index, self.slots_per_epoch) catch 0;

            const epoch = self.first_normal_epoch +| normal_epoch_index;
            const slot_index = std.math.rem(u64, normal_slot_index, self.slots_per_epoch) catch 0;

            return .{ epoch, slot_index };
        }
    }

    /// get the length of the given epoch (in slots)
    pub fn getSlotsInEpoch(self: *const EpochSchedule, epoch: Epoch) Slot {
        comptime std.debug.assert(std.math.isPowerOfTwo(MINIMUM_SLOTS_PER_EPOCH));
        return if (epoch < self.first_normal_epoch)
            @as(Slot, 1) <<| epoch +| @ctz(MINIMUM_SLOTS_PER_EPOCH)
        else
            self.slots_per_epoch;
    }

    pub fn random(rand: std.Random) EpochSchedule {
        return .{
            .slots_per_epoch = rand.int(u64),
            .leader_schedule_slot_offset = rand.int(u64),
            .warmup = rand.boolean(),
            .first_normal_epoch = rand.int(Epoch),
            .first_normal_slot = rand.int(Slot),
        };
    }
};

/// Analogous to [ClusterType](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/genesis_config.rs#L46)
pub const ClusterType = enum(u8) {
    Testnet,
    MainnetBeta,
    Devnet,
    Development,
};

/// Analogous to [GenesisConfig](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/genesis_config.rs#L93)
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
        return try bincode.read(allocator, GenesisConfig, file.reader(), .{});
    }

    pub fn deinit(self: GenesisConfig, allocator: std.mem.Allocator) void {
        bincode.free(allocator, self);
    }
};

test "genesis_config deserialize development config" {
    const allocator = std.testing.allocator;

    const genesis_path = "./test_data/genesis.bin";
    const config = try GenesisConfig.init(allocator, genesis_path);
    defer config.deinit(allocator);

    try std.testing.expect(config.cluster_type == ClusterType.Development);
}

test "genesis_config deserialize testnet config" {
    const allocator = std.testing.allocator;

    const genesis_path = "./genesis-files/testnet-genesis.bin";
    const config = try GenesisConfig.init(allocator, genesis_path);
    defer config.deinit(allocator);

    try std.testing.expect(config.cluster_type == ClusterType.Testnet);
}

test "genesis_config deserialize devnet config" {
    const allocator = std.testing.allocator;

    const genesis_path = "./genesis-files/devnet-genesis.bin";
    const config = try GenesisConfig.init(allocator, genesis_path);
    defer config.deinit(allocator);

    try std.testing.expect(config.cluster_type == ClusterType.Devnet);
}

test "genesis_config deserialize mainnet config" {
    const allocator = std.testing.allocator;

    const genesis_path = "./genesis-files/mainnet-genesis.bin";
    const config = try GenesisConfig.init(allocator, genesis_path);
    defer config.deinit(allocator);

    try std.testing.expect(config.cluster_type == ClusterType.MainnetBeta);
}
