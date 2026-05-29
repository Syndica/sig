const std = @import("std");
const sig = @import("../../lib.zig");
pub const ecc = @import("ecc.zig");

const Murmur3 = std.hash.Murmur3_32;
const Feature = sig.core.features.Feature;

pub const CurveId = ecc.CurveId;
pub const GroupOp = ecc.GroupOp;

pub const Syscall = enum {
    abort,
    sol_panic_,
    sol_alloc_free_,

    sol_log_,
    sol_log_64_,
    sol_log_pubkey,
    sol_log_compute_units_,
    sol_log_data,

    sol_create_program_address,
    sol_try_find_program_address,

    sol_sha256,
    sol_keccak256,
    sol_blake3,
    sol_poseidon,

    sol_secp256k1_recover,
    sol_curve_validate_point,
    sol_curve_group_op,
    sol_curve_multiscalar_mul,
    sol_alt_bn128_group_op,
    sol_alt_bn128_compression,

    sol_curve_decompress,
    sol_curve_pairing_map,

    sol_get_clock_sysvar,
    sol_get_epoch_schedule_sysvar,
    sol_get_fees_sysvar,
    sol_get_rent_sysvar,
    sol_get_last_restart_slot,
    sol_get_epoch_rewards_sysvar,

    sol_memcpy_,
    sol_memmove_,
    sol_memset_,
    sol_memcmp_,

    sol_get_processed_sibling_instruction,
    sol_get_stack_height,
    sol_set_return_data,
    sol_get_return_data,
    sol_get_sysvar,
    sol_get_epoch_stake,
    sol_remaining_compute_units,

    sol_invoke_signed_c,
    sol_invoke_signed_rust,

    pub const Registry = struct {
        map: std.EnumArray(Syscall, ?u32),
        is_stubbed: bool,

        pub const ALL_ENABLED: Registry = .{ .map = b: {
            var kvs: std.enums.EnumFieldStruct(Syscall, ?u32, null) = undefined;
            for (@typeInfo(Syscall).@"enum".fields) |field| {
                @field(kvs, field.name) = Murmur3.hashWithSeed(field.name, 0);
            }
            break :b .init(kvs);
        }, .is_stubbed = false };

        pub const ALL_DISABLED: Registry = .{ .map = .initFill(null), .is_stubbed = false };

        pub fn get(self: *const Registry, bytes: u32) ?Syscall {
            return for (self.map.values, 0..) |entry, i| {
                const value = entry orelse continue;
                if (value == bytes) break @enumFromInt(i);
            } else null;
        }

        pub fn enable(self: *Registry, name: Syscall) void {
            self.map.set(name, Murmur3.hashWithSeed(@tagName(name), 0));
        }
    };

    const Gate = struct {
        feature: Feature,
        invert: bool = false,
    };

    pub const gates = std.EnumArray(Syscall, ?Gate).initDefault(@as(?Gate, null), .{
        .sol_alloc_free_ = .{ .feature = .disable_deploy_of_alloc_free_syscall, .invert = true },

        .sol_blake3 = .{ .feature = .blake3_syscall_enabled },
        .sol_poseidon = .{ .feature = .enable_poseidon_syscall },

        .sol_curve_validate_point = .{ .feature = .curve25519_syscall_enabled },
        .sol_curve_group_op = .{ .feature = .curve25519_syscall_enabled },
        .sol_curve_multiscalar_mul = .{ .feature = .curve25519_syscall_enabled },
        .sol_alt_bn128_group_op = .{ .feature = .enable_alt_bn128_syscall },
        .sol_alt_bn128_compression = .{ .feature = .enable_alt_bn128_compression_syscall },

        .sol_curve_decompress = .{ .feature = .enable_bls12_381_syscall },
        .sol_curve_pairing_map = .{ .feature = .enable_bls12_381_syscall },

        .sol_get_fees_sysvar = .{ .feature = .disable_fees_sysvar, .invert = true },
        .sol_get_last_restart_slot = .{ .feature = .last_restart_slot_sysvar },
        .sol_remaining_compute_units = .{ .feature = .remaining_compute_units_syscall_enabled },
        .sol_get_sysvar = .{ .feature = .get_sysvar_syscall_enabled },
        .sol_get_epoch_stake = .{ .feature = .enable_get_epoch_stake_syscall },
    });
};

pub const gates = Syscall.gates;
