const std = @import("std");

/// Zig's `std.math.pow` may return a result that is off by up to one ULP, when comparing to glibc or musl's `pow()`.
/// As these calculations affect consensus, that is an unacceptable difference for us, so we import libc's pow and
/// use that. For reference:
/// - `std.math.pow`: pow(0.85, 4.019250798563942) -> 7.805634650110366e-2
/// - glibc/musl: pow(0.85, 4.019250798563942) -> 7.805634650110367e-2
extern fn pow(f64, f64) f64;

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
