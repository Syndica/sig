// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/clock/src/lib.rs
// https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/sysvar/fd_sysvar_clock.h

const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;

pub const Clock = struct {
    /// The current `Slot`.
    slot: Slot,
    /// The timestamp of the first `Slot` in this `Epoch`.
    epoch_start_timestamp: i64,
    /// The current `Epoch`.
    epoch: Epoch,
    /// The future `Epoch` for which the leader schedule has
    /// most recently been calculated.
    leader_schedule_epoch: Epoch,
    /// The approximate real world time of the current slot.
    ///
    /// This value was originally computed from genesis creation time and
    /// network time in slots, incurring a lot of drift. Following activation of
    /// the [`timestamp_correction` and `timestamp_bounding`][tsc] features it
    /// is calculated using a [validator timestamp oracle][oracle].
    ///
    /// [tsc]: https://docs.solanalabs.com/implemented-proposals/bank-timestamp-correction
    /// [oracle]: https://docs.solanalabs.com/implemented-proposals/validator-timestamp-oracle
    unix_timestamp: i64,
};
