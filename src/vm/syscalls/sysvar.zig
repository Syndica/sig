const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;
const memory = sig.vm.memory;
const sysvar = sig.runtime.sysvar;

const Error = sig.vm.syscalls.Error;
const Pubkey = sig.core.Pubkey;
const MemoryMap = memory.MemoryMap;
const InstructionError = sig.core.instruction.InstructionError;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const TransactionContext = sig.runtime.TransactionContext;

// https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/sysvar.rs#L164
const SYSVAR_NOT_FOUND = 2;
// https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/sysvar.rs#L165
const OFFSET_LENGTH_EXCEEDS_SYSVAR = 1;

fn getter(comptime T: type) fn (*TransactionContext, *MemoryMap, *RegisterMap) Error!void {
    return struct {
        fn getSyscall(
            tc: *TransactionContext,
            memory_map: *MemoryMap,
            registers: *RegisterMap,
        ) Error!void {
            try tc.consumeCompute(tc.compute_budget.sysvar_base_cost +| @sizeOf(T));

            const value_addr = registers.get(.r1);
            const value = try memory_map.translateType(
                T,
                .mutable,
                value_addr,
                tc.getCheckAligned(),
            );

            const v = try tc.sc.sysvar_cache.get(T);

            // Avoid value.* = v as it sets padding bytes to undefined instead of 0.
            value.* = std.mem.zeroes(T);
            inline for (std.meta.fields(T)) |f| @field(value, f.name) = @field(v, f.name);
        }
    }.getSyscall;
}

pub const getLastRestartSlot = getter(sysvar.LastRestartSlot);
pub const getRent = getter(sysvar.Rent);
pub const getFees = getter(sysvar.Fees);
pub const getEpochRewards = getter(sysvar.EpochRewards);
pub const getEpochSchedule = getter(sysvar.EpochSchedule);
pub const getClock = getter(sysvar.Clock);

/// [agave] https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/sysvar.rs#L169
pub fn getSysvar(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const id_addr = registers.get(.r1);
    const value_addr = registers.get(.r2);
    const offset = registers.get(.r3);
    const length = registers.get(.r4);

    const id_cost = std.math.divFloor(u64, 32, tc.compute_budget.cpi_bytes_per_unit) catch 0;
    const buf_cost = std.math.divFloor(u64, length, tc.compute_budget.cpi_bytes_per_unit) catch 0;
    const mem_cost = @max(tc.compute_budget.mem_op_base_cost, buf_cost);

    try tc.consumeCompute(tc.compute_budget.sysvar_base_cost +| id_cost +| mem_cost);

    const check_aligned = tc.getCheckAligned();
    const id = (try memory_map.translateType(Pubkey, .constant, id_addr, check_aligned)).*;
    const value = try memory_map.translateSlice(u8, .mutable, value_addr, length, check_aligned);

    const offset_len = std.math.add(u64, offset, length) catch
        return InstructionError.ProgramArithmeticOverflow;
    _ = std.math.add(u64, value_addr, length) catch
        return InstructionError.ProgramArithmeticOverflow;

    const buf = tc.sc.sysvar_cache.getSlice(id) orelse {
        return registers.set(.r0, SYSVAR_NOT_FOUND);
    };
    if (buf.len < offset_len) {
        return registers.set(.r0, OFFSET_LENGTH_EXCEEDS_SYSVAR);
    }

    @memcpy(value, buf[offset..][0..length]);
}

fn callSysvarSyscall(
    tc: *TransactionContext,
    memory_map: *memory.MemoryMap,
    comptime syscall_fn: fn (*TransactionContext, *MemoryMap, *RegisterMap) Error!void,
    args: anytype,
) !void {
    comptime std.debug.assert(builtin.is_test);

    var registers = RegisterMap.initFill(0);
    inline for (0..args.len) |i| registers.set(@enumFromInt(i + 1), args[i]);
    try syscall_fn(tc, memory_map, &registers);

    switch (registers.get(.r0)) {
        0 => {},
        SYSVAR_NOT_FOUND => return error.SysvarNotFound,
        OFFSET_LENGTH_EXCEEDS_SYSVAR => return error.OffsetLengthExceedsSysvar,
        else => unreachable,
    }
}

test getSysvar {
    const src = struct {
        const clock = fill(false, sysvar.Clock{
            .slot = 1,
            .epoch_start_timestamp = 2,
            .epoch = 3,
            .leader_schedule_epoch = 4,
            .unix_timestamp = 5,
        });
        const epoch_schedule = fill(false, sysvar.EpochSchedule{
            .slots_per_epoch = 1,
            .leader_schedule_slot_offset = 2,
            .warmup = false,
            .first_normal_epoch = 3,
            .first_normal_slot = 4,
        });
        const fees = fill(false, sysvar.Fees{
            .fee_calculator = .{ .lamports_per_signature = 1 },
        });
        const rent = fill(false, sysvar.Rent{
            .lamports_per_byte_year = 1,
            .exemption_threshold = 2.0,
            .burn_percent = 1,
        });
        const rewards = fill(false, sysvar.EpochRewards{
            .distribution_starting_block_height = 42,
            .num_partitions = 2,
            .parent_blockhash = .{ .data = .{3} ** 32 },
            .total_points = 4,
            .total_rewards = 100,
            .distributed_rewards = 10,
            .active = true,
        });
        const restart = fill(false, sysvar.LastRestartSlot{
            .last_restart_slot = 1,
        });

        fn fill(zeroed: bool, v: anytype) @TypeOf(v) {
            var new_v = @TypeOf(v).DEFAULT;
            for (std.mem.asBytes(&new_v), 0..) |*b, i| {
                b.* = if (zeroed) @as(u8, 0) else @intCast(i);
            }
            inline for (std.meta.fields(@TypeOf(v))) |field| {
                @field(new_v, field.name) = @field(v, field.name);
            }
            return new_v;
        }
    };

    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    const ec, const sc, var tc = try testing.createExecutionContexts(allocator, prng.random(), .{
        .accounts = &.{},
        .compute_meter = std.math.maxInt(u64),
        .sysvar_cache = .{
            .clock = src.clock,
            .epoch_schedule = src.epoch_schedule,
            .fees = src.fees,
            .rent = src.rent,
            .epoch_rewards = src.rewards,
            .last_restart_slot = src.restart,
        },
    });
    defer {
        ec.deinit();
        allocator.destroy(ec);
        sc.deinit();
        allocator.destroy(sc);
        tc.deinit();
    }

    // Test clock sysvar
    {
        var obj = sysvar.Clock.DEFAULT;
        const obj_addr = 0x100000000;

        var buffer = std.mem.zeroes([@sizeOf(sysvar.Clock)]u8);
        const buffer_addr = 0x200000000;
        const id_addr = 0x300000000;

        var clean_obj = src.fill(true, obj); // has bytes/padding zeroed.
        clean_obj.slot = src.clock.slot;
        clean_obj.epoch_start_timestamp = src.clock.epoch_start_timestamp;
        clean_obj.epoch = src.clock.epoch;
        clean_obj.leader_schedule_epoch = src.clock.leader_schedule_epoch;
        clean_obj.unix_timestamp = src.clock.unix_timestamp;

        var memory_map = try MemoryMap.init(
            allocator,
            &.{
                memory.Region.init(.mutable, std.mem.asBytes(&obj), obj_addr),
                memory.Region.init(.mutable, &buffer, buffer_addr),
                memory.Region.init(.constant, &sysvar.Clock.ID.data, id_addr),
            },
            .v3,
            .{},
        );
        defer memory_map.deinit(allocator);

        try callSysvarSyscall(&tc, &memory_map, getClock, .{obj_addr});
        try std.testing.expectEqual(obj, src.clock);
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&obj), std.mem.asBytes(&clean_obj));

        try callSysvarSyscall(&tc, &memory_map, getSysvar, .{
            id_addr,
            buffer_addr,
            0,
            @sizeOf(sysvar.Clock),
        });
        const obj_parsed = try bincode.readFromSlice(allocator, sysvar.Clock, &buffer, .{});
        try std.testing.expectEqual(obj_parsed, src.clock);
        try std.testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&obj_parsed),
            std.mem.asBytes(&clean_obj),
        );
    }

    // Test epoch_schedule sysvar
    {
        var obj = sysvar.EpochSchedule.DEFAULT;
        const obj_addr = 0x100000000;

        var buffer = std.mem.asBytes(&obj).*;
        const buffer_addr = 0x200000000;
        const id_addr = 0x300000000;

        var clean_obj = src.fill(true, obj); // has bytes/padding zeroed.
        clean_obj.slots_per_epoch = src.epoch_schedule.slots_per_epoch;
        clean_obj.leader_schedule_slot_offset = src.epoch_schedule.leader_schedule_slot_offset;
        clean_obj.warmup = src.epoch_schedule.warmup;
        clean_obj.first_normal_epoch = src.epoch_schedule.first_normal_epoch;
        clean_obj.first_normal_slot = src.epoch_schedule.first_normal_slot;

        var memory_map = try MemoryMap.init(
            allocator,
            &.{
                memory.Region.init(.mutable, std.mem.asBytes(&obj), obj_addr),
                memory.Region.init(.mutable, &buffer, buffer_addr),
                memory.Region.init(.constant, &sysvar.EpochSchedule.ID.data, id_addr),
            },
            .v3,
            .{},
        );
        defer memory_map.deinit(allocator);

        try callSysvarSyscall(&tc, &memory_map, getEpochSchedule, .{obj_addr});
        try std.testing.expectEqual(obj, src.epoch_schedule);
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&obj), std.mem.asBytes(&clean_obj));

        try callSysvarSyscall(&tc, &memory_map, getSysvar, .{
            id_addr,
            buffer_addr,
            0,
            @sizeOf(sysvar.EpochSchedule),
        });
        const obj_parsed = try bincode.readFromSlice(allocator, sysvar.EpochSchedule, &buffer, .{});
        try std.testing.expectEqual(obj_parsed, src.epoch_schedule);
        try std.testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&src.fill(true, obj_parsed)),
            std.mem.asBytes(&clean_obj),
        );
    }
}
