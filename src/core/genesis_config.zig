//! genesis config fields

const std = @import("std");
const sig = @import("../sig.zig");
const bincode = sig.bincode;

const Allocator = std.mem.Allocator;

const AutoHashMap = std.AutoHashMap;
const Account = sig.core.Account;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const Pubkey = sig.core.Pubkey;
const UnixTimestamp = sig.core.UnixTimestamp;
const Rent = sig.runtime.sysvar.Rent;

pub const String = std.array_list.Managed(u8);

pub const RustDuration = struct {
    secs: u64,
    nanos: u32,

    pub fn asNanos(self: RustDuration) u128 {
        return @as(u128, self.secs) * 1_000_000_000 + @as(u128, self.nanos);
    }
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

    pub const DEFAULT = PohConfig{
        .target_tick_duration = .{
            .secs = 0,
            .nanos = 1_000_000_000 / sig.core.time.DEFAULT_TICKS_PER_SECOND,
        },
        .target_tick_count = null,
        .hashes_per_tick = null,
    };
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

    pub const DEFAULT: FeeRateGovernor = .{
        .lamports_per_signature = 0,
        .target_lamports_per_signature = 10_000,
        .target_signatures_per_slot = 20_000,
        .min_lamports_per_signature = 0,
        .max_lamports_per_signature = 0,
        .burn_percent = 50,
    };

    pub fn initDerived(
        base: *const FeeRateGovernor,
        latest_signatures_per_slot: u64,
    ) FeeRateGovernor {
        if (base.target_signatures_per_slot == 0) {
            // this is the trivial case, which does not dynamically adjust fees
            // based on the number of signatures in the latest slot.
            return .{
                .target_signatures_per_slot = base.target_signatures_per_slot,
                .burn_percent = base.burn_percent,
                // set all lps rates to base.target_lamports_per_signature
                .lamports_per_signature = base.target_lamports_per_signature,
                .target_lamports_per_signature = base.target_lamports_per_signature,
                .min_lamports_per_signature = base.target_lamports_per_signature,
                .max_lamports_per_signature = base.target_lamports_per_signature,
            };
        }

        // ignore signatures exceeding 2^32
        const latest_signatures_per_slot_bounded = @min(
            latest_signatures_per_slot,
            @as(u64, std.math.maxInt(u32)),
        );

        // This is basically the fee rate that we'd like to charge, but it still
        // needs need to be constrained within some bounds.
        const unconstrained_fee_rate =
            base.target_lamports_per_signature *
            latest_signatures_per_slot_bounded /
            base.target_signatures_per_slot;

        // lamports_per_signature can range from 50% to 1000% of
        // target_lamports_per_signature
        const allowed_fee_range = [2]u64{
            @max(1, base.target_lamports_per_signature / 2),
            base.target_lamports_per_signature * 10,
        };

        // The rate that the cluster will start moving towards.
        const desired_fee_rate = clamp(allowed_fee_range, unconstrained_fee_rate);

        // The actual rate that will be used for the next slot.
        const lamports_per_signature = if (desired_fee_rate == base.lamports_per_signature)
            // We're already at the desired fee rate.
            desired_fee_rate
        else fee_rate: {
            // We're not at the desired fee rate, so adjust the fee by 5% of
            // target_lamports_per_signature to produce a gradual change in fees
            // over time.
            const adjustment_size: i64 = @intCast(@max(1, base.target_lamports_per_signature / 20));
            const adjustment = if (desired_fee_rate > base.lamports_per_signature)
                adjustment_size
            else
                -adjustment_size;

            const adjusted_fee_rate = @as(i64, @intCast(base.lamports_per_signature)) + adjustment;
            break :fee_rate clamp(allowed_fee_range, @intCast(adjusted_fee_rate));
        };

        return .{
            .lamports_per_signature = lamports_per_signature,
            .target_lamports_per_signature = base.target_lamports_per_signature,
            .target_signatures_per_slot = base.target_signatures_per_slot,
            .min_lamports_per_signature = allowed_fee_range[0],
            .max_lamports_per_signature = allowed_fee_range[1],
            .burn_percent = base.burn_percent,
        };
    }

    /// clamp input `n` such that it fits within the specified range.
    fn clamp(inclusive_range: [2]u64, n: u64) u64 {
        return @min(inclusive_range[1], @max(inclusive_range[0], n));
    }

    pub fn initRandom(random: std.Random) FeeRateGovernor {
        return .{
            .lamports_per_signature = random.int(u64),
            .target_lamports_per_signature = random.int(u64),
            .target_signatures_per_slot = random.int(u64),
            .min_lamports_per_signature = random.int(u64),
            .max_lamports_per_signature = random.int(u64),
            .burn_percent = random.uintAtMost(u8, 100),
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

    pub const DEFAULT = Inflation{
        .initial = 0.08,
        .terminal = 0.015,
        .taper = 0.15,
        .foundation = 0.05,
        .foundation_term = 7.0,
        .__unused = 0.0,
    };

    pub const FULL: Inflation = .{
        .initial = DEFAULT.initial,
        .terminal = DEFAULT.terminal,
        .taper = DEFAULT.taper,
        .foundation = 0.0,
        .foundation_term = 0.0,
        .__unused = 0.0,
    };

    pub const PICO = fixed(0.0001); // 0.01% inflation

    pub fn fixed(validator: f64) Inflation {
        return .{
            .initial = validator,
            .terminal = validator,
            .taper = 1.0,
            .foundation = 0.0,
            .foundation_term = 0.0,
            .__unused = 0.0,
        };
    }

    pub fn initRandom(random: std.Random) Inflation {
        return .{
            .initial = random.float(f64),
            .terminal = random.float(f64),
            .taper = random.float(f64),
            .foundation = random.float(f64),
            .foundation_term = random.float(f64),
            .__unused = random.float(f64),
        };
    }

    pub fn total(self: *const Inflation, slot_in_years: f64) f64 {
        std.debug.assert(slot_in_years >= 0.0);
        return @max(
            self.terminal,
            self.initial * pow(1.0 - self.taper, slot_in_years),
        );
    }

    pub fn validatorRate(self: *const Inflation, slot_in_years: f64) f64 {
        std.debug.assert(slot_in_years >= 0.0);
        return self.total(slot_in_years) - self.foundationRate(slot_in_years);
    }

    pub fn foundationRate(self: *const Inflation, slot_in_years: f64) f64 {
        return if (slot_in_years < self.foundation_term)
            self.total(slot_in_years) * self.foundation
        else
            0.0;
    }
};

/// Analogous to [ClusterType](https://github.com/anza-xyz/solana-sdk/blob/a467058aabc453c7d749a4993c56df293d1d75c3/cluster-type/src/lib.rs#L19)
/// Explicit numbers are added to ensure we don't mess up the order of the fields and break bincode reading.
pub const ClusterType = enum(u8) {
    testnet = 0,
    mainnet = 1,
    devnet = 2,
    development = 3,

    /// Returns entrypoints for public clusters, null for development.
    /// For development this returns an empty list, because the caller
    /// must provide entrypoints manually.
    pub fn getEntrypoints(self: ClusterType) []const []const u8 {
        return switch (self) {
            .mainnet => &.{
                "entrypoint.mainnet-beta.solana.com:8001",
                "entrypoint2.mainnet-beta.solana.com:8001",
                "entrypoint3.mainnet-beta.solana.com:8001",
                "entrypoint4.mainnet-beta.solana.com:8001",
                "entrypoint5.mainnet-beta.solana.com:8001",
            },
            .testnet => &.{
                "entrypoint.testnet.solana.com:8001",
                "entrypoint2.testnet.solana.com:8001",
                "entrypoint3.testnet.solana.com:8001",
            },
            .devnet => &.{
                "entrypoint.devnet.solana.com:8001",
                "entrypoint2.devnet.solana.com:8001",
                "entrypoint3.devnet.solana.com:8001",
                "entrypoint4.devnet.solana.com:8001",
                "entrypoint5.devnet.solana.com:8001",
            },
            .development => &.{},
        };
    }

    /// Returns the RPC URL for this cluster.
    pub fn getRpcUrl(self: ClusterType) ?[]const u8 {
        return switch (self) {
            .mainnet => "https://api.mainnet-beta.solana.com",
            .testnet => "https://api.testnet.solana.com",
            .devnet => "https://api.devnet.solana.com",
            .development => null,
        };
    }
};

/// Analogous to [GenesisConfig](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/genesis_config.rs#L93)
pub const GenesisConfig = struct {
    // when the network (bootstrap validator) was started relative to the UNIX Epoch
    creation_time: UnixTimestamp,
    // initial accounts
    accounts: AutoHashMap(Pubkey, Account),
    // /// built-in programs
    native_instruction_processors: std.array_list.Managed(struct { String, Pubkey }),
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
    /// hash of the serialized genesis config, computed after deserialization
    hash: sig.core.Hash = sig.core.Hash.ZEROES,

    pub const @"!bincode-config:hash" = bincode.FieldConfig(sig.core.Hash){ .skip = true };

    pub fn init(allocator: Allocator, genesis_path: []const u8) !GenesisConfig {
        var file = try std.fs.cwd().openFile(genesis_path, .{});
        defer file.close();

        // Read the entire file to compute hash from raw bytes
        const file_bytes = try file.readToEndAlloc(allocator, 100 * 1024 * 1024); // 100 MB max
        defer allocator.free(file_bytes);

        // Compute hash from original file bytes
        // [agave] https://github.com/anza-xyz/solana-sdk/blob/f2d15de6f7a1715ff806f0c39bba8f64bf6a587d/genesis-config/src/lib.rs#L144
        var hash_bytes: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(file_bytes, &hash_bytes, .{});

        // Parse the genesis config from the bytes
        var config = try bincode.readFromSlice(allocator, GenesisConfig, file_bytes, .{});
        config.hash.data = hash_bytes;
        return config;
    }

    pub fn default(allocator: Allocator) GenesisConfig {
        return .{
            .creation_time = 0,
            .accounts = .init(allocator),
            .native_instruction_processors = .init(allocator),
            .rewards_pools = .init(allocator),
            .ticks_per_slot = sig.core.time.DEFAULT_TICKS_PER_SLOT,
            .unused = 1024,
            .poh_config = .DEFAULT,
            .inflation = .DEFAULT,
            .__backwards_compat_with_v0_23 = 0,
            .fee_rate_governor = .DEFAULT,
            .rent = .INIT,
            .epoch_schedule = .INIT,
            .cluster_type = .development,
        };
    }

    pub fn deinit(self: GenesisConfig, allocator: Allocator) void {
        bincode.free(allocator, self);
    }

    pub fn nsPerSlot(self: *const GenesisConfig) u128 {
        return self.poh_config.target_tick_duration.asNanos() *| @as(u128, self.ticks_per_slot);
    }

    pub fn slotsPerYear(self: *const GenesisConfig) f64 {
        return yearsAsSlots(1.0, self.poh_config.target_tick_duration, self.ticks_per_slot);
    }
};

fn yearsAsSlots(years: f64, tick_duration: RustDuration, ticks_per_slot: u64) f64 {
    const SECONDS_PER_YEAR: f64 = 365.242_199 * 24.0 * 60.0 * 60.0;
    const SLOTS_PER_YEAR = SECONDS_PER_YEAR *
        (1_000_000_000.0 / @as(f64, @floatFromInt(tick_duration.asNanos()))) /
        @as(f64, @floatFromInt(ticks_per_slot));

    return years * SLOTS_PER_YEAR;
}

/// Zig's `std.math.pow` may return a result that is off by up to one ULP, when comparing to glibc or musl's `pow()`.
/// As these calculations affect consensus, that is an unacceptable difference for us, so we import libc's pow and
/// use that. For reference:
/// - `std.math.pow`: pow(0.85, 4.019250798563942) -> 7.805634650110366e-2
/// - glibc/musl: pow(0.85, 4.019250798563942) -> 7.805634650110367e-2
extern fn pow(f64, f64) f64;

test "genesis_config deserialize development config" {
    const allocator = std.testing.allocator;

    const genesis_path = sig.TEST_DATA_DIR ++ "genesis.bin";
    const config = try GenesisConfig.init(allocator, genesis_path);
    defer config.deinit(allocator);

    try std.testing.expectEqual(ClusterType.development, config.cluster_type);
}

test "genesis_config deserialize testnet config" {
    const allocator = std.testing.allocator;

    const genesis_path = sig.GENESIS_DIR ++ "testnet_genesis.bin";
    const config = try GenesisConfig.init(allocator, genesis_path);
    defer config.deinit(allocator);

    try std.testing.expectEqual(ClusterType.testnet, config.cluster_type);
    try std.testing.expectEqualStrings(
        "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
        config.hash.base58String().constSlice(),
    );
}

test "genesis_config deserialize devnet config" {
    const allocator = std.testing.allocator;

    const genesis_path = sig.GENESIS_DIR ++ "devnet_genesis.bin";
    const config = try GenesisConfig.init(allocator, genesis_path);
    defer config.deinit(allocator);

    try std.testing.expectEqual(ClusterType.devnet, config.cluster_type);
    try std.testing.expectEqualStrings(
        "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
        config.hash.base58String().constSlice(),
    );
}

test "genesis_config deserialize mainnet config" {
    const allocator = std.testing.allocator;

    const genesis_path = sig.GENESIS_DIR ++ "mainnet_genesis.bin";
    const config = try GenesisConfig.init(allocator, genesis_path);
    defer config.deinit(allocator);

    try std.testing.expectEqual(ClusterType.mainnet, config.cluster_type);
    try std.testing.expectEqualStrings(
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        config.hash.base58String().constSlice(),
    );
}

test "inflation" {
    const inflation = Inflation{
        .initial = 0.15,
        .terminal = 0.015,
        .taper = 0.15,
        .foundation = 0.0,
        .foundation_term = 0.0,
        .__unused = 0.0,
    };

    try std.testing.expectEqual(7.805634650110367e-2, inflation.total(4.019250798563942));
    std.debug.assert(4602862346652160054 == @as(u64, @bitCast(pow(0.85, 4.019250798563942))));
}

// cases generated randomly with this code:
// ```rust
// fn random_fee_rate_governor(rng: &mut rand::rngs::ThreadRng) {
//     let test_edges = rng.next_u32() % 5 != 0;
//     let input = FeeRateGovernor {
//         lamports_per_signature: random(&mut rng, test_edges),
//         target_lamports_per_signature: random(&mut rng, test_edges),
//         target_signatures_per_slot: random(&mut rng, test_edges),
//         min_lamports_per_signature: random(&mut rng, test_edges),
//         max_lamports_per_signature: random(&mut rng, test_edges),
//         burn_percent: (random(&mut rng, test_edges) % 256) as u8,
//     };
//     let num_sigs = random(&mut rng, test_edges);
//     let new = FeeRateGovernor::new_derived(&input, num_sigs);
//     println!("inputs: {input:?}, {num_sigs}\n new: {new:?}\n")
// }
//
// fn random(rng: &mut rand::rngs::ThreadRng, edges: bool) -> u64 {
//     let number = rng.next_u32();
//     let switch = rng.next_u32() % 10;
//
//     if !edges {
//         return number as u64;
//     }
//
//     if switch == 0 {
//         0
//     } else if switch == 2 {
//         1
//     } else if switch == 3 {
//         (number % 256) as u64
//     } else {
//         number as u64
//     }
// }
// ```
test "FeeRateGovernor.initDerived conforms with agave" {
    // zig fmt: off
    var input = FeeRateGovernor{ .lamports_per_signature = 1569526149, .target_lamports_per_signature = 1498255309, .target_signatures_per_slot = 3177457594, .min_lamports_per_signature = 0, .max_lamports_per_signature = 3419321597, .burn_percent = 201 };
    var latest_signatures_per_slot: u64 = 3591040104;
    var expected = FeeRateGovernor{ .lamports_per_signature = 1644438914, .target_lamports_per_signature = 1498255309, .target_signatures_per_slot = 3177457594, .min_lamports_per_signature = 749127654, .max_lamports_per_signature = 14982553090, .burn_percent = 201 };
    var actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 336794257, .target_lamports_per_signature = 0, .target_signatures_per_slot = 0, .min_lamports_per_signature = 423863421, .max_lamports_per_signature = 50, .burn_percent = 176 };
    latest_signatures_per_slot = 1222375991;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 0, .min_lamports_per_signature = 0, .max_lamports_per_signature = 0, .burn_percent = 176 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 225, .target_lamports_per_signature = 4168736594, .target_signatures_per_slot = 1554176388, .min_lamports_per_signature = 3377284916, .max_lamports_per_signature = 1751707793, .burn_percent = 0 };
    latest_signatures_per_slot = 3935135205;
    expected = FeeRateGovernor{ .lamports_per_signature = 2084368297, .target_lamports_per_signature = 4168736594, .target_signatures_per_slot = 1554176388, .min_lamports_per_signature = 2084368297, .max_lamports_per_signature = 41687365940, .burn_percent = 0 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3218716105, .target_lamports_per_signature = 2332767933, .target_signatures_per_slot = 979012614, .min_lamports_per_signature = 3447138858, .max_lamports_per_signature = 1957388903, .burn_percent = 145 };
    latest_signatures_per_slot = 1278137578;
    expected = FeeRateGovernor{ .lamports_per_signature = 3102077709, .target_lamports_per_signature = 2332767933, .target_signatures_per_slot = 979012614, .min_lamports_per_signature = 1166383966, .max_lamports_per_signature = 23327679330, .burn_percent = 145 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual); // failed previously

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 4003207591, .target_signatures_per_slot = 393170618, .min_lamports_per_signature = 101, .max_lamports_per_signature = 157, .burn_percent = 106 };
    latest_signatures_per_slot = 1763297866;
    expected = FeeRateGovernor{ .lamports_per_signature = 2001603795, .target_lamports_per_signature = 4003207591, .target_signatures_per_slot = 393170618, .min_lamports_per_signature = 2001603795, .max_lamports_per_signature = 40032075910, .burn_percent = 106 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2289765803, .target_lamports_per_signature = 422933400, .target_signatures_per_slot = 1342861665, .min_lamports_per_signature = 1, .max_lamports_per_signature = 1764730161, .burn_percent = 136 };
    latest_signatures_per_slot = 543210270;
    expected = FeeRateGovernor{ .lamports_per_signature = 2268619133, .target_lamports_per_signature = 422933400, .target_signatures_per_slot = 1342861665, .min_lamports_per_signature = 211466700, .max_lamports_per_signature = 4229334000, .burn_percent = 136 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3693233487, .target_lamports_per_signature = 369519360, .target_signatures_per_slot = 3742356144, .min_lamports_per_signature = 3763786741, .max_lamports_per_signature = 60799843, .burn_percent = 237 };
    latest_signatures_per_slot = 205;
    expected = FeeRateGovernor{ .lamports_per_signature = 3674757519, .target_lamports_per_signature = 369519360, .target_signatures_per_slot = 3742356144, .min_lamports_per_signature = 184759680, .max_lamports_per_signature = 3695193600, .burn_percent = 237 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2164179769, .target_lamports_per_signature = 1643805672, .target_signatures_per_slot = 0, .min_lamports_per_signature = 1, .max_lamports_per_signature = 1177788175, .burn_percent = 0 };
    latest_signatures_per_slot = 2444016984;
    expected = FeeRateGovernor{ .lamports_per_signature = 1643805672, .target_lamports_per_signature = 1643805672, .target_signatures_per_slot = 0, .min_lamports_per_signature = 1643805672, .max_lamports_per_signature = 1643805672, .burn_percent = 0 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1590665714, .target_lamports_per_signature = 2809223945, .target_signatures_per_slot = 2849266213, .min_lamports_per_signature = 2319961789, .max_lamports_per_signature = 1551906958, .burn_percent = 102 };
    latest_signatures_per_slot = 1748825227;
    expected = FeeRateGovernor{ .lamports_per_signature = 1731126911, .target_lamports_per_signature = 2809223945, .target_signatures_per_slot = 2849266213, .min_lamports_per_signature = 1404611972, .max_lamports_per_signature = 28092239450, .burn_percent = 102 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual); // failed previously

    input = FeeRateGovernor{ .lamports_per_signature = 1193392132, .target_lamports_per_signature = 1173303215, .target_signatures_per_slot = 3875535763, .min_lamports_per_signature = 1408763493, .max_lamports_per_signature = 0, .burn_percent = 0 };
    latest_signatures_per_slot = 417211408;
    expected = FeeRateGovernor{ .lamports_per_signature = 1134726972, .target_lamports_per_signature = 1173303215, .target_signatures_per_slot = 3875535763, .min_lamports_per_signature = 586651607, .max_lamports_per_signature = 11733032150, .burn_percent = 0 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 121, .target_lamports_per_signature = 2819798288, .target_signatures_per_slot = 2626280166, .min_lamports_per_signature = 3658703907, .max_lamports_per_signature = 1728672559, .burn_percent = 86 };
    latest_signatures_per_slot = 3706794916;
    expected = FeeRateGovernor{ .lamports_per_signature = 1409899144, .target_lamports_per_signature = 2819798288, .target_signatures_per_slot = 2626280166, .min_lamports_per_signature = 1409899144, .max_lamports_per_signature = 28197982880, .burn_percent = 86 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 837730615, .target_lamports_per_signature = 2893037135, .target_signatures_per_slot = 2214940952, .min_lamports_per_signature = 3032441778, .max_lamports_per_signature = 1149430937, .burn_percent = 41 };
    latest_signatures_per_slot = 548898929;
    expected = FeeRateGovernor{ .lamports_per_signature = 1446518567, .target_lamports_per_signature = 2893037135, .target_signatures_per_slot = 2214940952, .min_lamports_per_signature = 1446518567, .max_lamports_per_signature = 28930371350, .burn_percent = 41 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3245409384, .target_lamports_per_signature = 0, .target_signatures_per_slot = 201, .min_lamports_per_signature = 3865774298, .max_lamports_per_signature = 2574714787, .burn_percent = 200 };
    latest_signatures_per_slot = 2290518472;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 201, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 200 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual); // failed previously

    input = FeeRateGovernor{ .lamports_per_signature = 1998499872, .target_lamports_per_signature = 1792899161, .target_signatures_per_slot = 0, .min_lamports_per_signature = 2379508751, .max_lamports_per_signature = 3746567032, .burn_percent = 112 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 1792899161, .target_lamports_per_signature = 1792899161, .target_signatures_per_slot = 0, .min_lamports_per_signature = 1792899161, .max_lamports_per_signature = 1792899161, .burn_percent = 112 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 3003873994, .target_signatures_per_slot = 2122251000, .min_lamports_per_signature = 645660971, .max_lamports_per_signature = 1, .burn_percent = 62 };
    latest_signatures_per_slot = 0;
    expected = FeeRateGovernor{ .lamports_per_signature = 1501936997, .target_lamports_per_signature = 3003873994, .target_signatures_per_slot = 2122251000, .min_lamports_per_signature = 1501936997, .max_lamports_per_signature = 30038739940, .burn_percent = 62 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 1, .target_signatures_per_slot = 2212343777, .min_lamports_per_signature = 945452796, .max_lamports_per_signature = 14, .burn_percent = 1 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 1, .target_lamports_per_signature = 1, .target_signatures_per_slot = 2212343777, .min_lamports_per_signature = 1, .max_lamports_per_signature = 10, .burn_percent = 1 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 1, .target_signatures_per_slot = 1931337166, .min_lamports_per_signature = 3825933480, .max_lamports_per_signature = 0, .burn_percent = 82 };
    latest_signatures_per_slot = 0;
    expected = FeeRateGovernor{ .lamports_per_signature = 1, .target_lamports_per_signature = 1, .target_signatures_per_slot = 1931337166, .min_lamports_per_signature = 1, .max_lamports_per_signature = 10, .burn_percent = 82 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1887953778, .target_lamports_per_signature = 3662461538, .target_signatures_per_slot = 3566122033, .min_lamports_per_signature = 60, .max_lamports_per_signature = 208, .burn_percent = 131 };
    latest_signatures_per_slot = 2349519587;
    expected = FeeRateGovernor{ .lamports_per_signature = 2071076854, .target_lamports_per_signature = 3662461538, .target_signatures_per_slot = 3566122033, .min_lamports_per_signature = 1831230769, .max_lamports_per_signature = 36624615380, .burn_percent = 131 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1235897954, .target_lamports_per_signature = 4192844989, .target_signatures_per_slot = 195, .min_lamports_per_signature = 532566125, .max_lamports_per_signature = 0, .burn_percent = 0 };
    latest_signatures_per_slot = 3551046081;
    expected = FeeRateGovernor{ .lamports_per_signature = 2096422494, .target_lamports_per_signature = 4192844989, .target_signatures_per_slot = 195, .min_lamports_per_signature = 2096422494, .max_lamports_per_signature = 41928449890, .burn_percent = 0 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1740750763, .target_lamports_per_signature = 3934164382, .target_signatures_per_slot = 2671643812, .min_lamports_per_signature = 2435441687, .max_lamports_per_signature = 2445167253, .burn_percent = 136 };
    latest_signatures_per_slot = 2924683607;
    expected = FeeRateGovernor{ .lamports_per_signature = 1967082191, .target_lamports_per_signature = 3934164382, .target_signatures_per_slot = 2671643812, .min_lamports_per_signature = 1967082191, .max_lamports_per_signature = 39341643820, .burn_percent = 136 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3846366385, .target_lamports_per_signature = 0, .target_signatures_per_slot = 0, .min_lamports_per_signature = 1210440536, .max_lamports_per_signature = 1497978625, .burn_percent = 149 };
    latest_signatures_per_slot = 2774623712;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 0, .min_lamports_per_signature = 0, .max_lamports_per_signature = 0, .burn_percent = 149 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3714268514, .target_lamports_per_signature = 948878635, .target_signatures_per_slot = 3036048423, .min_lamports_per_signature = 2391935893, .max_lamports_per_signature = 568787211, .burn_percent = 165 };
    latest_signatures_per_slot = 1093811003;
    expected = FeeRateGovernor{ .lamports_per_signature = 3666824583, .target_lamports_per_signature = 948878635, .target_signatures_per_slot = 3036048423, .min_lamports_per_signature = 474439317, .max_lamports_per_signature = 9488786350, .burn_percent = 165 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1803186858, .target_lamports_per_signature = 3509493935, .target_signatures_per_slot = 222, .min_lamports_per_signature = 1171426968, .max_lamports_per_signature = 4209020038, .burn_percent = 141 };
    latest_signatures_per_slot = 1769506291;
    expected = FeeRateGovernor{ .lamports_per_signature = 1978661554, .target_lamports_per_signature = 3509493935, .target_signatures_per_slot = 222, .min_lamports_per_signature = 1754746967, .max_lamports_per_signature = 35094939350, .burn_percent = 141 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 3759017143, .target_signatures_per_slot = 3342607027, .min_lamports_per_signature = 3388972278, .max_lamports_per_signature = 1176923950, .burn_percent = 125 };
    latest_signatures_per_slot = 1561254573;
    expected = FeeRateGovernor{ .lamports_per_signature = 1879508571, .target_lamports_per_signature = 3759017143, .target_signatures_per_slot = 3342607027, .min_lamports_per_signature = 1879508571, .max_lamports_per_signature = 37590171430, .burn_percent = 125 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 93855054, .target_lamports_per_signature = 1088196912, .target_signatures_per_slot = 3231419265, .min_lamports_per_signature = 3496630134, .max_lamports_per_signature = 3908536063, .burn_percent = 17 };
    latest_signatures_per_slot = 2696514815;
    expected = FeeRateGovernor{ .lamports_per_signature = 544098456, .target_lamports_per_signature = 1088196912, .target_signatures_per_slot = 3231419265, .min_lamports_per_signature = 544098456, .max_lamports_per_signature = 10881969120, .burn_percent = 17 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 330338919, .target_lamports_per_signature = 2318206390, .target_signatures_per_slot = 2585150928, .min_lamports_per_signature = 1754885202, .max_lamports_per_signature = 2441203679, .burn_percent = 155 };
    latest_signatures_per_slot = 98179415;
    expected = FeeRateGovernor{ .lamports_per_signature = 1159103195, .target_lamports_per_signature = 2318206390, .target_signatures_per_slot = 2585150928, .min_lamports_per_signature = 1159103195, .max_lamports_per_signature = 23182063900, .burn_percent = 155 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1723145971, .target_lamports_per_signature = 2938975181, .target_signatures_per_slot = 22057991, .min_lamports_per_signature = 4093243212, .max_lamports_per_signature = 8936501, .burn_percent = 58 };
    latest_signatures_per_slot = 3857664481;
    expected = FeeRateGovernor{ .lamports_per_signature = 1870094730, .target_lamports_per_signature = 2938975181, .target_signatures_per_slot = 22057991, .min_lamports_per_signature = 1469487590, .max_lamports_per_signature = 29389751810, .burn_percent = 58 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 687112846, .target_lamports_per_signature = 0, .target_signatures_per_slot = 14968787, .min_lamports_per_signature = 1, .max_lamports_per_signature = 997886161, .burn_percent = 103 };
    latest_signatures_per_slot = 1476256292;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 14968787, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 103 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1258961203, .target_lamports_per_signature = 3197013538, .target_signatures_per_slot = 1558068390, .min_lamports_per_signature = 2635297991, .max_lamports_per_signature = 251573458, .burn_percent = 78 };
    latest_signatures_per_slot = 3893607856;
    expected = FeeRateGovernor{ .lamports_per_signature = 1598506769, .target_lamports_per_signature = 3197013538, .target_signatures_per_slot = 1558068390, .min_lamports_per_signature = 1598506769, .max_lamports_per_signature = 31970135380, .burn_percent = 78 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 119, .target_lamports_per_signature = 3024780136, .target_signatures_per_slot = 2324198573, .min_lamports_per_signature = 120, .max_lamports_per_signature = 286617210, .burn_percent = 0 };
    latest_signatures_per_slot = 2412422688;
    expected = FeeRateGovernor{ .lamports_per_signature = 1512390068, .target_lamports_per_signature = 3024780136, .target_signatures_per_slot = 2324198573, .min_lamports_per_signature = 1512390068, .max_lamports_per_signature = 30247801360, .burn_percent = 0 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 264756857, .target_lamports_per_signature = 1366178964, .target_signatures_per_slot = 2440293422, .min_lamports_per_signature = 582860950, .max_lamports_per_signature = 137, .burn_percent = 137 };
    latest_signatures_per_slot = 2588647;
    expected = FeeRateGovernor{ .lamports_per_signature = 683089482, .target_lamports_per_signature = 1366178964, .target_signatures_per_slot = 2440293422, .min_lamports_per_signature = 683089482, .max_lamports_per_signature = 13661789640, .burn_percent = 137 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1941732044, .target_lamports_per_signature = 337514605, .target_signatures_per_slot = 4078267988, .min_lamports_per_signature = 424448256, .max_lamports_per_signature = 2363008724, .burn_percent = 156 };
    latest_signatures_per_slot = 3975659937;
    expected = FeeRateGovernor{ .lamports_per_signature = 1924856314, .target_lamports_per_signature = 337514605, .target_signatures_per_slot = 4078267988, .min_lamports_per_signature = 168757302, .max_lamports_per_signature = 3375146050, .burn_percent = 156 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 4220174333, .target_lamports_per_signature = 56, .target_signatures_per_slot = 4212393487, .min_lamports_per_signature = 3724406332, .max_lamports_per_signature = 1909517718, .burn_percent = 92 };
    latest_signatures_per_slot = 212;
    expected = FeeRateGovernor{ .lamports_per_signature = 560, .target_lamports_per_signature = 56, .target_signatures_per_slot = 4212393487, .min_lamports_per_signature = 28, .max_lamports_per_signature = 560, .burn_percent = 92 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2741962727, .target_lamports_per_signature = 4013532749, .target_signatures_per_slot = 1069711218, .min_lamports_per_signature = 2177615662, .max_lamports_per_signature = 1193752903, .burn_percent = 7 };
    latest_signatures_per_slot = 2065973196;
    expected = FeeRateGovernor{ .lamports_per_signature = 2942639364, .target_lamports_per_signature = 4013532749, .target_signatures_per_slot = 1069711218, .min_lamports_per_signature = 2006766374, .max_lamports_per_signature = 40135327490, .burn_percent = 7 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2605276372, .target_lamports_per_signature = 3894494271, .target_signatures_per_slot = 199, .min_lamports_per_signature = 0, .max_lamports_per_signature = 2089857860, .burn_percent = 0 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 2410551659, .target_lamports_per_signature = 3894494271, .target_signatures_per_slot = 199, .min_lamports_per_signature = 1947247135, .max_lamports_per_signature = 38944942710, .burn_percent = 0 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 453679453, .target_lamports_per_signature = 989200297, .target_signatures_per_slot = 3250688437, .min_lamports_per_signature = 2743964405, .max_lamports_per_signature = 4099015644, .burn_percent = 64 };
    latest_signatures_per_slot = 2240802186;
    expected = FeeRateGovernor{ .lamports_per_signature = 503139467, .target_lamports_per_signature = 989200297, .target_signatures_per_slot = 3250688437, .min_lamports_per_signature = 494600148, .max_lamports_per_signature = 9892002970, .burn_percent = 64 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 134, .target_lamports_per_signature = 0, .target_signatures_per_slot = 2554792720, .min_lamports_per_signature = 3972613785, .max_lamports_per_signature = 4100957523, .burn_percent = 33 };
    latest_signatures_per_slot = 2368544217;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 2554792720, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 33 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 3093854710, .target_signatures_per_slot = 667774637, .min_lamports_per_signature = 133122496, .max_lamports_per_signature = 1045270606, .burn_percent = 108 };
    latest_signatures_per_slot = 1461843461;
    expected = FeeRateGovernor{ .lamports_per_signature = 1546927355, .target_lamports_per_signature = 3093854710, .target_signatures_per_slot = 667774637, .min_lamports_per_signature = 1546927355, .max_lamports_per_signature = 30938547100, .burn_percent = 108 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2240689707, .target_lamports_per_signature = 2837492207, .target_signatures_per_slot = 2902001095, .min_lamports_per_signature = 284221076, .max_lamports_per_signature = 1669059037, .burn_percent = 230 };
    latest_signatures_per_slot = 1598920295;
    expected = FeeRateGovernor{ .lamports_per_signature = 2098815097, .target_lamports_per_signature = 2837492207, .target_signatures_per_slot = 2902001095, .min_lamports_per_signature = 1418746103, .max_lamports_per_signature = 28374922070, .burn_percent = 230 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 4240564111, .target_lamports_per_signature = 2108347724, .target_signatures_per_slot = 38, .min_lamports_per_signature = 19739908, .max_lamports_per_signature = 451422699, .burn_percent = 0 };
    latest_signatures_per_slot = 1710209848;
    expected = FeeRateGovernor{ .lamports_per_signature = 4345981497, .target_lamports_per_signature = 2108347724, .target_signatures_per_slot = 38, .min_lamports_per_signature = 1054173862, .max_lamports_per_signature = 21083477240, .burn_percent = 0 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1, .target_lamports_per_signature = 4101716458, .target_signatures_per_slot = 1, .min_lamports_per_signature = 337881100, .max_lamports_per_signature = 2486922996, .burn_percent = 50 };
    latest_signatures_per_slot = 3700185208;
    expected = FeeRateGovernor{ .lamports_per_signature = 2050858229, .target_lamports_per_signature = 4101716458, .target_signatures_per_slot = 1, .min_lamports_per_signature = 2050858229, .max_lamports_per_signature = 41017164580, .burn_percent = 50 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3368943190, .target_lamports_per_signature = 3378893536, .target_signatures_per_slot = 2081562967, .min_lamports_per_signature = 2669703015, .max_lamports_per_signature = 3182590875, .burn_percent = 216 };
    latest_signatures_per_slot = 2405649160;
    expected = FeeRateGovernor{ .lamports_per_signature = 3537887866, .target_lamports_per_signature = 3378893536, .target_signatures_per_slot = 2081562967, .min_lamports_per_signature = 1689446768, .max_lamports_per_signature = 33788935360, .burn_percent = 216 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 594159151, .target_lamports_per_signature = 1, .target_signatures_per_slot = 1202884641, .min_lamports_per_signature = 2227129833, .max_lamports_per_signature = 3502420615, .burn_percent = 196 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 10, .target_lamports_per_signature = 1, .target_signatures_per_slot = 1202884641, .min_lamports_per_signature = 1, .max_lamports_per_signature = 10, .burn_percent = 196 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 80, .target_lamports_per_signature = 3168900081, .target_signatures_per_slot = 67, .min_lamports_per_signature = 1780843117, .max_lamports_per_signature = 4215939123, .burn_percent = 1 };
    latest_signatures_per_slot = 194;
    expected = FeeRateGovernor{ .lamports_per_signature = 1584450040, .target_lamports_per_signature = 3168900081, .target_signatures_per_slot = 67, .min_lamports_per_signature = 1584450040, .max_lamports_per_signature = 31689000810, .burn_percent = 1 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3496060715, .target_lamports_per_signature = 865098657, .target_signatures_per_slot = 1, .min_lamports_per_signature = 3430530746, .max_lamports_per_signature = 1080003154, .burn_percent = 84 };
    latest_signatures_per_slot = 181;
    expected = FeeRateGovernor{ .lamports_per_signature = 3539315647, .target_lamports_per_signature = 865098657, .target_signatures_per_slot = 1, .min_lamports_per_signature = 432549328, .max_lamports_per_signature = 8650986570, .burn_percent = 84 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1431385661, .target_lamports_per_signature = 471260120, .target_signatures_per_slot = 0, .min_lamports_per_signature = 2283341352, .max_lamports_per_signature = 4274638505, .burn_percent = 24 };
    latest_signatures_per_slot = 714184052;
    expected = FeeRateGovernor{ .lamports_per_signature = 471260120, .target_lamports_per_signature = 471260120, .target_signatures_per_slot = 0, .min_lamports_per_signature = 471260120, .max_lamports_per_signature = 471260120, .burn_percent = 24 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 606954585, .target_lamports_per_signature = 169850326, .target_signatures_per_slot = 909345551, .min_lamports_per_signature = 2846016508, .max_lamports_per_signature = 4202491507, .burn_percent = 133 };
    latest_signatures_per_slot = 2561297384;
    expected = FeeRateGovernor{ .lamports_per_signature = 598462069, .target_lamports_per_signature = 169850326, .target_signatures_per_slot = 909345551, .min_lamports_per_signature = 84925163, .max_lamports_per_signature = 1698503260, .burn_percent = 133 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3028494728, .target_lamports_per_signature = 4043349631, .target_signatures_per_slot = 4186088670, .min_lamports_per_signature = 2776870649, .max_lamports_per_signature = 4019316950, .burn_percent = 206 };
    latest_signatures_per_slot = 2356137847;
    expected = FeeRateGovernor{ .lamports_per_signature = 2826327247, .target_lamports_per_signature = 4043349631, .target_signatures_per_slot = 4186088670, .min_lamports_per_signature = 2021674815, .max_lamports_per_signature = 40433496310, .burn_percent = 206 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2211547690, .target_lamports_per_signature = 2955633421, .target_signatures_per_slot = 1, .min_lamports_per_signature = 2974008354, .max_lamports_per_signature = 4069568398, .burn_percent = 131 };
    latest_signatures_per_slot = 3248303084;
    expected = FeeRateGovernor{ .lamports_per_signature = 2359329361, .target_lamports_per_signature = 2955633421, .target_signatures_per_slot = 1, .min_lamports_per_signature = 1477816710, .max_lamports_per_signature = 29556334210, .burn_percent = 131 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1, .target_lamports_per_signature = 0, .target_signatures_per_slot = 1332311029, .min_lamports_per_signature = 4211236673, .max_lamports_per_signature = 77670235, .burn_percent = 176 };
    latest_signatures_per_slot = 29;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 1332311029, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 176 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1, .target_lamports_per_signature = 1901350317, .target_signatures_per_slot = 0, .min_lamports_per_signature = 0, .max_lamports_per_signature = 0, .burn_percent = 144 };
    latest_signatures_per_slot = 3025058622;
    expected = FeeRateGovernor{ .lamports_per_signature = 1901350317, .target_lamports_per_signature = 1901350317, .target_signatures_per_slot = 0, .min_lamports_per_signature = 1901350317, .max_lamports_per_signature = 1901350317, .burn_percent = 144 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 893646572, .target_lamports_per_signature = 0, .target_signatures_per_slot = 3118133536, .min_lamports_per_signature = 3553413135, .max_lamports_per_signature = 2529128836, .burn_percent = 39 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 3118133536, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 39 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2734813770, .target_lamports_per_signature = 3220139421, .target_signatures_per_slot = 3413789546, .min_lamports_per_signature = 3008804941, .max_lamports_per_signature = 3843016895, .burn_percent = 210 };
    latest_signatures_per_slot = 1567251501;
    expected = FeeRateGovernor{ .lamports_per_signature = 2573806799, .target_lamports_per_signature = 3220139421, .target_signatures_per_slot = 3413789546, .min_lamports_per_signature = 1610069710, .max_lamports_per_signature = 32201394210, .burn_percent = 210 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3673222840, .target_lamports_per_signature = 180, .target_signatures_per_slot = 808114639, .min_lamports_per_signature = 3141327234, .max_lamports_per_signature = 1750645938, .burn_percent = 186 };
    latest_signatures_per_slot = 3545016099;
    expected = FeeRateGovernor{ .lamports_per_signature = 1800, .target_lamports_per_signature = 180, .target_signatures_per_slot = 808114639, .min_lamports_per_signature = 90, .max_lamports_per_signature = 1800, .burn_percent = 186 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1919213465, .target_lamports_per_signature = 156540101, .target_signatures_per_slot = 371803026, .min_lamports_per_signature = 3978651640, .max_lamports_per_signature = 1352080173, .burn_percent = 212 };
    latest_signatures_per_slot = 2265338874;
    expected = FeeRateGovernor{ .lamports_per_signature = 1565401010, .target_lamports_per_signature = 156540101, .target_signatures_per_slot = 371803026, .min_lamports_per_signature = 78270050, .max_lamports_per_signature = 1565401010, .burn_percent = 212 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3591161517, .target_lamports_per_signature = 1675829409, .target_signatures_per_slot = 1993532181, .min_lamports_per_signature = 3262935724, .max_lamports_per_signature = 2147593865, .burn_percent = 130 };
    latest_signatures_per_slot = 1825460661;
    expected = FeeRateGovernor{ .lamports_per_signature = 3507370047, .target_lamports_per_signature = 1675829409, .target_signatures_per_slot = 1993532181, .min_lamports_per_signature = 837914704, .max_lamports_per_signature = 16758294090, .burn_percent = 130 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1399200051, .target_lamports_per_signature = 1619570489, .target_signatures_per_slot = 2037207489, .min_lamports_per_signature = 1582962081, .max_lamports_per_signature = 574189401, .burn_percent = 211 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 1318221527, .target_lamports_per_signature = 1619570489, .target_signatures_per_slot = 2037207489, .min_lamports_per_signature = 809785244, .max_lamports_per_signature = 16195704890, .burn_percent = 211 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1975235953, .target_lamports_per_signature = 3777732488, .target_signatures_per_slot = 234, .min_lamports_per_signature = 184, .max_lamports_per_signature = 4124174087, .burn_percent = 242 };
    latest_signatures_per_slot = 0;
    expected = FeeRateGovernor{ .lamports_per_signature = 1888866244, .target_lamports_per_signature = 3777732488, .target_signatures_per_slot = 234, .min_lamports_per_signature = 1888866244, .max_lamports_per_signature = 37777324880, .burn_percent = 242 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2553811634, .target_lamports_per_signature = 2450675901, .target_signatures_per_slot = 0, .min_lamports_per_signature = 242, .max_lamports_per_signature = 100, .burn_percent = 1 };
    latest_signatures_per_slot = 0;
    expected = FeeRateGovernor{ .lamports_per_signature = 2450675901, .target_lamports_per_signature = 2450675901, .target_signatures_per_slot = 0, .min_lamports_per_signature = 2450675901, .max_lamports_per_signature = 2450675901, .burn_percent = 1 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1, .target_lamports_per_signature = 145, .target_signatures_per_slot = 854432934, .min_lamports_per_signature = 2610526791, .max_lamports_per_signature = 606975316, .burn_percent = 213 };
    latest_signatures_per_slot = 0;
    expected = FeeRateGovernor{ .lamports_per_signature = 72, .target_lamports_per_signature = 145, .target_signatures_per_slot = 854432934, .min_lamports_per_signature = 72, .max_lamports_per_signature = 1450, .burn_percent = 213 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 816348698, .target_lamports_per_signature = 401655461, .target_signatures_per_slot = 1580986373, .min_lamports_per_signature = 1585922283, .max_lamports_per_signature = 3723293071, .burn_percent = 1 };
    latest_signatures_per_slot = 3904764297;
    expected = FeeRateGovernor{ .lamports_per_signature = 836431471, .target_lamports_per_signature = 401655461, .target_signatures_per_slot = 1580986373, .min_lamports_per_signature = 200827730, .max_lamports_per_signature = 4016554610, .burn_percent = 1 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3702012367, .target_lamports_per_signature = 2005912922, .target_signatures_per_slot = 230017858, .min_lamports_per_signature = 1153001223, .max_lamports_per_signature = 163, .burn_percent = 158 };
    latest_signatures_per_slot = 4013471332;
    expected = FeeRateGovernor{ .lamports_per_signature = 3802308013, .target_lamports_per_signature = 2005912922, .target_signatures_per_slot = 230017858, .min_lamports_per_signature = 1002956461, .max_lamports_per_signature = 20059129220, .burn_percent = 158 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 4285846394, .target_lamports_per_signature = 3321413426, .target_signatures_per_slot = 1669118970, .min_lamports_per_signature = 3935052120, .max_lamports_per_signature = 1989239249, .burn_percent = 176 };
    latest_signatures_per_slot = 247522595;
    expected = FeeRateGovernor{ .lamports_per_signature = 4119775723, .target_lamports_per_signature = 3321413426, .target_signatures_per_slot = 1669118970, .min_lamports_per_signature = 1660706713, .max_lamports_per_signature = 33214134260, .burn_percent = 176 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 4144082822, .target_lamports_per_signature = 2388923652, .target_signatures_per_slot = 1, .min_lamports_per_signature = 1498320198, .max_lamports_per_signature = 912791205, .burn_percent = 206 };
    latest_signatures_per_slot = 1253559052;
    expected = FeeRateGovernor{ .lamports_per_signature = 4263529004, .target_lamports_per_signature = 2388923652, .target_signatures_per_slot = 1, .min_lamports_per_signature = 1194461826, .max_lamports_per_signature = 23889236520, .burn_percent = 206 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1316827383, .target_lamports_per_signature = 3318948968, .target_signatures_per_slot = 969416205, .min_lamports_per_signature = 2449387098, .max_lamports_per_signature = 888384292, .burn_percent = 42 };
    latest_signatures_per_slot = 965387581;
    expected = FeeRateGovernor{ .lamports_per_signature = 1659474484, .target_lamports_per_signature = 3318948968, .target_signatures_per_slot = 969416205, .min_lamports_per_signature = 1659474484, .max_lamports_per_signature = 33189489680, .burn_percent = 42 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 3414648719, .target_signatures_per_slot = 2606317420, .min_lamports_per_signature = 1134985858, .max_lamports_per_signature = 1035132128, .burn_percent = 80 };
    latest_signatures_per_slot = 3607349623;
    expected = FeeRateGovernor{ .lamports_per_signature = 1707324359, .target_lamports_per_signature = 3414648719, .target_signatures_per_slot = 2606317420, .min_lamports_per_signature = 1707324359, .max_lamports_per_signature = 34146487190, .burn_percent = 80 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 248907616, .target_lamports_per_signature = 1050686130, .target_signatures_per_slot = 2291040181, .min_lamports_per_signature = 0, .max_lamports_per_signature = 805102012, .burn_percent = 1 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 525343065, .target_lamports_per_signature = 1050686130, .target_signatures_per_slot = 2291040181, .min_lamports_per_signature = 525343065, .max_lamports_per_signature = 10506861300, .burn_percent = 1 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1, .target_lamports_per_signature = 4229966102, .target_signatures_per_slot = 1, .min_lamports_per_signature = 489746242, .max_lamports_per_signature = 241, .burn_percent = 166 };
    latest_signatures_per_slot = 1572600498;
    expected = FeeRateGovernor{ .lamports_per_signature = 2114983051, .target_lamports_per_signature = 4229966102, .target_signatures_per_slot = 1, .min_lamports_per_signature = 2114983051, .max_lamports_per_signature = 42299661020, .burn_percent = 166 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2289903379, .target_lamports_per_signature = 3687527747, .target_signatures_per_slot = 0, .min_lamports_per_signature = 295286352, .max_lamports_per_signature = 4256746500, .burn_percent = 128 };
    latest_signatures_per_slot = 148;
    expected = FeeRateGovernor{ .lamports_per_signature = 3687527747, .target_lamports_per_signature = 3687527747, .target_signatures_per_slot = 0, .min_lamports_per_signature = 3687527747, .max_lamports_per_signature = 3687527747, .burn_percent = 128 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 62, .target_lamports_per_signature = 417333628, .target_signatures_per_slot = 1250549525, .min_lamports_per_signature = 0, .max_lamports_per_signature = 1476873537, .burn_percent = 159 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 208666814, .target_lamports_per_signature = 417333628, .target_signatures_per_slot = 1250549525, .min_lamports_per_signature = 208666814, .max_lamports_per_signature = 4173336280, .burn_percent = 159 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1231906201, .target_lamports_per_signature = 172, .target_signatures_per_slot = 1, .min_lamports_per_signature = 321337072, .max_lamports_per_signature = 4151395352, .burn_percent = 1 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 1720, .target_lamports_per_signature = 172, .target_signatures_per_slot = 1, .min_lamports_per_signature = 86, .max_lamports_per_signature = 1720, .burn_percent = 1 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 92, .target_lamports_per_signature = 2341514415, .target_signatures_per_slot = 1522722485, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 138 };
    latest_signatures_per_slot = 92;
    expected = FeeRateGovernor{ .lamports_per_signature = 1170757207, .target_lamports_per_signature = 2341514415, .target_signatures_per_slot = 1522722485, .min_lamports_per_signature = 1170757207, .max_lamports_per_signature = 23415144150, .burn_percent = 138 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1470863706, .target_lamports_per_signature = 4032288588, .target_signatures_per_slot = 1, .min_lamports_per_signature = 4110789287, .max_lamports_per_signature = 0, .burn_percent = 1 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 2016144294, .target_lamports_per_signature = 4032288588, .target_signatures_per_slot = 1, .min_lamports_per_signature = 2016144294, .max_lamports_per_signature = 40322885880, .burn_percent = 1 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 73954197, .target_lamports_per_signature = 3841077568, .target_signatures_per_slot = 717685677, .min_lamports_per_signature = 2387394218, .max_lamports_per_signature = 3730773401, .burn_percent = 131 };
    latest_signatures_per_slot = 950176993;
    expected = FeeRateGovernor{ .lamports_per_signature = 1920538784, .target_lamports_per_signature = 3841077568, .target_signatures_per_slot = 717685677, .min_lamports_per_signature = 1920538784, .max_lamports_per_signature = 38410775680, .burn_percent = 131 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 1445110712, .target_signatures_per_slot = 3179995019, .min_lamports_per_signature = 0, .max_lamports_per_signature = 0, .burn_percent = 37 };
    latest_signatures_per_slot = 724256821;
    expected = FeeRateGovernor{ .lamports_per_signature = 722555356, .target_lamports_per_signature = 1445110712, .target_signatures_per_slot = 3179995019, .min_lamports_per_signature = 722555356, .max_lamports_per_signature = 14451107120, .burn_percent = 37 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 36, .target_lamports_per_signature = 1, .target_signatures_per_slot = 1254088016, .min_lamports_per_signature = 3677918140, .max_lamports_per_signature = 710108393, .burn_percent = 238 };
    latest_signatures_per_slot = 3168594366;
    expected = FeeRateGovernor{ .lamports_per_signature = 10, .target_lamports_per_signature = 1, .target_signatures_per_slot = 1254088016, .min_lamports_per_signature = 1, .max_lamports_per_signature = 10, .burn_percent = 238 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1909211482, .target_lamports_per_signature = 1, .target_signatures_per_slot = 4282456091, .min_lamports_per_signature = 3113631012, .max_lamports_per_signature = 3118612824, .burn_percent = 119 };
    latest_signatures_per_slot = 196;
    expected = FeeRateGovernor{ .lamports_per_signature = 10, .target_lamports_per_signature = 1, .target_signatures_per_slot = 4282456091, .min_lamports_per_signature = 1, .max_lamports_per_signature = 10, .burn_percent = 119 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 1904162324, .target_signatures_per_slot = 2124464016, .min_lamports_per_signature = 0, .max_lamports_per_signature = 82, .burn_percent = 111 };
    latest_signatures_per_slot = 1705330566;
    expected = FeeRateGovernor{ .lamports_per_signature = 952081162, .target_lamports_per_signature = 1904162324, .target_signatures_per_slot = 2124464016, .min_lamports_per_signature = 952081162, .max_lamports_per_signature = 19041623240, .burn_percent = 111 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3786585530, .target_lamports_per_signature = 1, .target_signatures_per_slot = 3531906757, .min_lamports_per_signature = 2705743480, .max_lamports_per_signature = 0, .burn_percent = 1 };
    latest_signatures_per_slot = 610737406;
    expected = FeeRateGovernor{ .lamports_per_signature = 10, .target_lamports_per_signature = 1, .target_signatures_per_slot = 3531906757, .min_lamports_per_signature = 1, .max_lamports_per_signature = 10, .burn_percent = 1 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 116657766, .target_lamports_per_signature = 1503510589, .target_signatures_per_slot = 3043282548, .min_lamports_per_signature = 24, .max_lamports_per_signature = 1381495062, .burn_percent = 193 };
    latest_signatures_per_slot = 2075201472;
    expected = FeeRateGovernor{ .lamports_per_signature = 751755294, .target_lamports_per_signature = 1503510589, .target_signatures_per_slot = 3043282548, .min_lamports_per_signature = 751755294, .max_lamports_per_signature = 15035105890, .burn_percent = 193 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 4176346762, .target_lamports_per_signature = 1659158901, .target_signatures_per_slot = 4027942331, .min_lamports_per_signature = 2202817437, .max_lamports_per_signature = 1, .burn_percent = 204 };
    latest_signatures_per_slot = 4090220524;
    expected = FeeRateGovernor{ .lamports_per_signature = 4093388817, .target_lamports_per_signature = 1659158901, .target_signatures_per_slot = 4027942331, .min_lamports_per_signature = 829579450, .max_lamports_per_signature = 16591589010, .burn_percent = 204 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3980668843, .target_lamports_per_signature = 251, .target_signatures_per_slot = 2562637286, .min_lamports_per_signature = 3692204823, .max_lamports_per_signature = 1569613828, .burn_percent = 225 };
    latest_signatures_per_slot = 4014010368;
    expected = FeeRateGovernor{ .lamports_per_signature = 2510, .target_lamports_per_signature = 251, .target_signatures_per_slot = 2562637286, .min_lamports_per_signature = 125, .max_lamports_per_signature = 2510, .burn_percent = 225 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2581876069, .target_lamports_per_signature = 0, .target_signatures_per_slot = 3061189376, .min_lamports_per_signature = 2995480096, .max_lamports_per_signature = 2906604592, .burn_percent = 209 };
    latest_signatures_per_slot = 1;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 3061189376, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 209 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 849012190, .target_signatures_per_slot = 1142771856, .min_lamports_per_signature = 0, .max_lamports_per_signature = 1690244747, .burn_percent = 192 };
    latest_signatures_per_slot = 88;
    expected = FeeRateGovernor{ .lamports_per_signature = 424506095, .target_lamports_per_signature = 849012190, .target_signatures_per_slot = 1142771856, .min_lamports_per_signature = 424506095, .max_lamports_per_signature = 8490121900, .burn_percent = 192 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3059367009, .target_lamports_per_signature = 2042203442, .target_signatures_per_slot = 2602054559, .min_lamports_per_signature = 3081919306, .max_lamports_per_signature = 1, .burn_percent = 210 };
    latest_signatures_per_slot = 79;
    expected = FeeRateGovernor{ .lamports_per_signature = 2957256837, .target_lamports_per_signature = 2042203442, .target_signatures_per_slot = 2602054559, .min_lamports_per_signature = 1021101721, .max_lamports_per_signature = 20422034420, .burn_percent = 210 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2545157736, .target_lamports_per_signature = 3181714642, .target_signatures_per_slot = 0, .min_lamports_per_signature = 3875288364, .max_lamports_per_signature = 0, .burn_percent = 170 };
    latest_signatures_per_slot = 0;
    expected = FeeRateGovernor{ .lamports_per_signature = 3181714642, .target_lamports_per_signature = 3181714642, .target_signatures_per_slot = 0, .min_lamports_per_signature = 3181714642, .max_lamports_per_signature = 3181714642, .burn_percent = 170 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3765273301, .target_lamports_per_signature = 1, .target_signatures_per_slot = 172, .min_lamports_per_signature = 138, .max_lamports_per_signature = 1, .burn_percent = 1 };
    latest_signatures_per_slot = 0;
    expected = FeeRateGovernor{ .lamports_per_signature = 10, .target_lamports_per_signature = 1, .target_signatures_per_slot = 172, .min_lamports_per_signature = 1, .max_lamports_per_signature = 10, .burn_percent = 1 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3686768930, .target_lamports_per_signature = 4222017364, .target_signatures_per_slot = 0, .min_lamports_per_signature = 27, .max_lamports_per_signature = 1314427861, .burn_percent = 135 };
    latest_signatures_per_slot = 4033439027;
    expected = FeeRateGovernor{ .lamports_per_signature = 4222017364, .target_lamports_per_signature = 4222017364, .target_signatures_per_slot = 0, .min_lamports_per_signature = 4222017364, .max_lamports_per_signature = 4222017364, .burn_percent = 135 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2965554780, .target_lamports_per_signature = 0, .target_signatures_per_slot = 1, .min_lamports_per_signature = 3924063286, .max_lamports_per_signature = 2947006861, .burn_percent = 112 };
    latest_signatures_per_slot = 1450928091;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 1, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 112 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 773989765, .target_lamports_per_signature = 1204835925, .target_signatures_per_slot = 4138242352, .min_lamports_per_signature = 4287369882, .max_lamports_per_signature = 1186598483, .burn_percent = 45 };
    latest_signatures_per_slot = 256454503;
    expected = FeeRateGovernor{ .lamports_per_signature = 713747969, .target_lamports_per_signature = 1204835925, .target_signatures_per_slot = 4138242352, .min_lamports_per_signature = 602417962, .max_lamports_per_signature = 12048359250, .burn_percent = 45 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2163930933, .target_lamports_per_signature = 586819263, .target_signatures_per_slot = 603970998, .min_lamports_per_signature = 432755243, .max_lamports_per_signature = 2091698928, .burn_percent = 2 };
    latest_signatures_per_slot = 1599352870;
    expected = FeeRateGovernor{ .lamports_per_signature = 2134589970, .target_lamports_per_signature = 586819263, .target_signatures_per_slot = 603970998, .min_lamports_per_signature = 293409631, .max_lamports_per_signature = 5868192630, .burn_percent = 2 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1417547241, .target_lamports_per_signature = 3893246225, .target_signatures_per_slot = 2366368571, .min_lamports_per_signature = 2627355771, .max_lamports_per_signature = 1511212390, .burn_percent = 28 };
    latest_signatures_per_slot = 4162590676;
    expected = FeeRateGovernor{ .lamports_per_signature = 1946623112, .target_lamports_per_signature = 3893246225, .target_signatures_per_slot = 2366368571, .min_lamports_per_signature = 1946623112, .max_lamports_per_signature = 38932462250, .burn_percent = 28 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1301597118, .target_lamports_per_signature = 1996374443, .target_signatures_per_slot = 86, .min_lamports_per_signature = 0, .max_lamports_per_signature = 3218745967, .burn_percent = 118 };
    latest_signatures_per_slot = 1358296834;
    expected = FeeRateGovernor{ .lamports_per_signature = 1401415840, .target_lamports_per_signature = 1996374443, .target_signatures_per_slot = 86, .min_lamports_per_signature = 998187221, .max_lamports_per_signature = 19963744430, .burn_percent = 118 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2396769531, .target_lamports_per_signature = 0, .target_signatures_per_slot = 2823006008, .min_lamports_per_signature = 1113465400, .max_lamports_per_signature = 2803021074, .burn_percent = 60 };
    latest_signatures_per_slot = 201699299;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 2823006008, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 60 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 143142108, .target_lamports_per_signature = 3385859278, .target_signatures_per_slot = 3454080525, .min_lamports_per_signature = 0, .max_lamports_per_signature = 3290122110, .burn_percent = 43 };
    latest_signatures_per_slot = 204;
    expected = FeeRateGovernor{ .lamports_per_signature = 1692929639, .target_lamports_per_signature = 3385859278, .target_signatures_per_slot = 3454080525, .min_lamports_per_signature = 1692929639, .max_lamports_per_signature = 33858592780, .burn_percent = 43 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 2404419313, .target_lamports_per_signature = 97, .target_signatures_per_slot = 2569425702, .min_lamports_per_signature = 596435366, .max_lamports_per_signature = 3464749166, .burn_percent = 102 };
    latest_signatures_per_slot = 527480391;
    expected = FeeRateGovernor{ .lamports_per_signature = 970, .target_lamports_per_signature = 97, .target_signatures_per_slot = 2569425702, .min_lamports_per_signature = 48, .max_lamports_per_signature = 970, .burn_percent = 102 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1402023004, .target_lamports_per_signature = 1373834219, .target_signatures_per_slot = 882408769, .min_lamports_per_signature = 1196350372, .max_lamports_per_signature = 1019600611, .burn_percent = 184 };
    latest_signatures_per_slot = 1219807273;
    expected = FeeRateGovernor{ .lamports_per_signature = 1470714714, .target_lamports_per_signature = 1373834219, .target_signatures_per_slot = 882408769, .min_lamports_per_signature = 686917109, .max_lamports_per_signature = 13738342190, .burn_percent = 184 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 1635341056, .target_lamports_per_signature = 3645229593, .target_signatures_per_slot = 0, .min_lamports_per_signature = 303394666, .max_lamports_per_signature = 1736977611, .burn_percent = 174 };
    latest_signatures_per_slot = 2647115418;
    expected = FeeRateGovernor{ .lamports_per_signature = 3645229593, .target_lamports_per_signature = 3645229593, .target_signatures_per_slot = 0, .min_lamports_per_signature = 3645229593, .max_lamports_per_signature = 3645229593, .burn_percent = 174 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 3440397621, .target_lamports_per_signature = 913678961, .target_signatures_per_slot = 0, .min_lamports_per_signature = 1, .max_lamports_per_signature = 191, .burn_percent = 208 };
    latest_signatures_per_slot = 822056961;
    expected = FeeRateGovernor{ .lamports_per_signature = 913678961, .target_lamports_per_signature = 913678961, .target_signatures_per_slot = 0, .min_lamports_per_signature = 913678961, .max_lamports_per_signature = 913678961, .burn_percent = 208 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);

    input = FeeRateGovernor{ .lamports_per_signature = 297639466, .target_lamports_per_signature = 0, .target_signatures_per_slot = 3285008881, .min_lamports_per_signature = 236, .max_lamports_per_signature = 1553787450, .burn_percent = 105 };
    latest_signatures_per_slot = 1328442079;
    expected = FeeRateGovernor{ .lamports_per_signature = 0, .target_lamports_per_signature = 0, .target_signatures_per_slot = 3285008881, .min_lamports_per_signature = 1, .max_lamports_per_signature = 0, .burn_percent = 105 };
    actual = FeeRateGovernor.initDerived(&input, latest_signatures_per_slot);
    try std.testing.expectEqual(expected, actual);
    // zig fmt: on
}
