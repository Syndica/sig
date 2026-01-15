const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;
const memory = sig.vm.memory;
const sysvar = sig.runtime.sysvar;

const Hash = sig.core.Hash;
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

fn getSyscall(comptime T: type) fn (*TransactionContext, *MemoryMap, *RegisterMap) Error!void {
    comptime std.debug.assert(@typeInfo(T).@"struct".layout == .@"extern");
    return struct {
        fn getSyscall(
            tc: *TransactionContext,
            memory_map: *MemoryMap,
            registers: *RegisterMap,
        ) Error!void {
            try tc.consumeCompute(tc.compute_budget.sysvar_base_cost + @sizeOf(T));

            const value_addr = registers.get(.r1);
            const value = try memory_map.translateType(
                T,
                .mutable,
                value_addr,
                tc.getCheckAligned(),
            );

            const v = try tc.sysvar_cache.get(T);

            // Avoid value.* = v as it sets padding bytes to undefined instead of 0.
            @memset(std.mem.asBytes(value), 0);
            inline for (@typeInfo(T).@"struct".fields) |f| {
                @field(value, f.name) = @field(v, f.name);
            }
        }
    }.getSyscall;
}

pub const getLastRestartSlot = getSyscall(sysvar.LastRestartSlot);
pub const getRent = getSyscall(sysvar.Rent);
pub const getFees = getSyscall(sysvar.Fees);
pub const getEpochRewards = getSyscall(sysvar.EpochRewards);
pub const getEpochSchedule = getSyscall(sysvar.EpochSchedule);
pub const getClock = getSyscall(sysvar.Clock);

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

    const id_cost = Pubkey.SIZE / tc.compute_budget.cpi_bytes_per_unit;
    const buf_cost = length / tc.compute_budget.cpi_bytes_per_unit;
    const mem_cost = @max(tc.compute_budget.mem_op_base_cost, buf_cost);
    try tc.consumeCompute(tc.compute_budget.sysvar_base_cost +| id_cost +| mem_cost);

    const check_aligned = tc.getCheckAligned();
    const id = (try memory_map.translateType(Pubkey, .constant, id_addr, check_aligned)).*;
    const value = try memory_map.translateSlice(u8, .mutable, value_addr, length, check_aligned);

    const offset_plus_len = std.math.add(u64, offset, length) catch
        return InstructionError.ProgramArithmeticOverflow;
    _ = std.math.add(u64, value_addr, length) catch
        return InstructionError.ProgramArithmeticOverflow;

    const buf = tc.sysvar_cache.getSlice(id) orelse {
        registers.set(.r0, SYSVAR_NOT_FOUND);
        return;
    };

    if (buf.len < offset_plus_len) {
        registers.set(.r0, OFFSET_LENGTH_EXCEEDS_SYSVAR);
        return;
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
            .lamports_per_signature = 1,
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
            var new_v = @TypeOf(v).INIT;
            if (zeroed) {
                @memset(std.mem.asBytes(&new_v), 0);
            } else {
                for (std.mem.asBytes(&new_v), 0..) |*b, i| {
                    b.* = @intCast(i);
                }
            }
            inline for (@typeInfo(@TypeOf(v)).@"struct".fields) |field| {
                @field(new_v, field.name) = @field(v, field.name);
            }
            return new_v;
        }
    };

    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
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
        testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    // // Test clock sysvar
    {
        var obj = sysvar.Clock.INIT;
        const obj_addr = 0x100000000;

        var buffer = std.mem.zeroes([sysvar.Clock.STORAGE_SIZE]u8);
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
            sysvar.Clock.STORAGE_SIZE,
        });

        const obj_parsed = try bincode.readFromSlice(
            std.testing.failing_allocator, // this shouldnt need to allocate
            sysvar.Clock,
            &buffer,
            .{},
        );
        try std.testing.expectEqual(obj_parsed, src.clock);
        try std.testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&obj_parsed),
            std.mem.asBytes(&clean_obj),
        );
    }

    // // Test epoch_schedule sysvar
    {
        var obj = sysvar.EpochSchedule.INIT;
        const obj_addr = 0x100000000;

        var buffer = std.mem.zeroes([sysvar.EpochSchedule.STORAGE_SIZE]u8);
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
            sysvar.EpochSchedule.STORAGE_SIZE,
        });
        const obj_parsed = try bincode.readFromSlice(
            std.testing.failing_allocator, // this shouldnt need to allocate
            sysvar.EpochSchedule,
            &buffer,
            .{},
        );
        try std.testing.expectEqual(obj_parsed, src.epoch_schedule);
        try std.testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&src.fill(true, obj_parsed)),
            std.mem.asBytes(&clean_obj),
        );
    }

    // Test fees sysvar
    {
        var obj = sysvar.Fees.INIT;
        const obj_addr = 0x100000000;

        var clean_obj = src.fill(true, obj); // has bytes/padding zeroed.
        clean_obj = src.fees;

        var memory_map = try MemoryMap.init(
            allocator,
            &.{memory.Region.init(.mutable, std.mem.asBytes(&obj), obj_addr)},
            .v3,
            .{},
        );
        defer memory_map.deinit(allocator);

        try callSysvarSyscall(&tc, &memory_map, getFees, .{obj_addr});
        try std.testing.expectEqual(obj, src.fees);
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&obj), std.mem.asBytes(&clean_obj));

        // fees sysvar is not accessed via sol_get_sysvar so nothing further to test
    }

    // Test rent sysvar
    {
        var obj = src.fill(true, sysvar.Rent.INIT);
        const obj_addr = 0x100000000;

        var buffer = std.mem.zeroes([sysvar.Rent.STORAGE_SIZE]u8);
        const buffer_addr = 0x200000000;
        const id_addr = 0x300000000;

        var clean_obj = src.fill(true, obj); // has bytes/padding zeroed.
        clean_obj.lamports_per_byte_year = src.rent.lamports_per_byte_year;
        clean_obj.exemption_threshold = src.rent.exemption_threshold;
        clean_obj.burn_percent = src.rent.burn_percent;

        var memory_map = try MemoryMap.init(
            allocator,
            &.{
                memory.Region.init(.mutable, std.mem.asBytes(&obj), obj_addr),
                memory.Region.init(.mutable, &buffer, buffer_addr),
                memory.Region.init(.constant, &sysvar.Rent.ID.data, id_addr),
            },
            .v3,
            .{},
        );
        defer memory_map.deinit(allocator);

        try callSysvarSyscall(&tc, &memory_map, getRent, .{obj_addr});
        try std.testing.expectEqual(obj, src.rent);
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&obj), std.mem.asBytes(&clean_obj));

        try callSysvarSyscall(&tc, &memory_map, getSysvar, .{
            id_addr,
            buffer_addr,
            0,
            sysvar.Rent.STORAGE_SIZE,
        });
        const obj_parsed = try bincode.readFromSlice(
            std.testing.failing_allocator, // this shouldnt need to allocate
            sysvar.Rent,
            &buffer,
            .{},
        );
        try std.testing.expectEqual(obj_parsed, src.rent);
        try std.testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&src.fill(true, obj_parsed)),
            std.mem.asBytes(&clean_obj),
        );
    }

    // Test epoch rewards sysvar
    {
        var obj = src.fill(true, sysvar.EpochRewards.INIT);
        const obj_addr = 0x100000000;

        var buffer = std.mem.zeroes([sysvar.EpochRewards.STORAGE_SIZE]u8);
        const buffer_addr = 0x200000000;
        const id_addr = 0x300000000;

        var clean_obj = src.fill(true, obj); // has bytes/padding zeroed.
        clean_obj.distribution_starting_block_height =
            src.rewards.distribution_starting_block_height;
        clean_obj.num_partitions = src.rewards.num_partitions;
        clean_obj.parent_blockhash = src.rewards.parent_blockhash;
        clean_obj.total_points = src.rewards.total_points;
        clean_obj.total_rewards = src.rewards.total_rewards;
        clean_obj.distributed_rewards = src.rewards.distributed_rewards;
        clean_obj.active = src.rewards.active;

        var memory_map = try MemoryMap.init(
            allocator,
            &.{
                memory.Region.init(.mutable, std.mem.asBytes(&obj), obj_addr),
                memory.Region.init(.mutable, &buffer, buffer_addr),
                memory.Region.init(.constant, &sysvar.EpochRewards.ID.data, id_addr),
            },
            .v3,
            .{},
        );
        defer memory_map.deinit(allocator);

        try callSysvarSyscall(&tc, &memory_map, getEpochRewards, .{obj_addr});
        try std.testing.expectEqual(obj, src.rewards);
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&obj), std.mem.asBytes(&clean_obj));

        try callSysvarSyscall(&tc, &memory_map, getSysvar, .{
            id_addr,
            buffer_addr,
            0,
            sysvar.EpochRewards.STORAGE_SIZE,
        });
        const obj_parsed = try bincode.readFromSlice(
            std.testing.failing_allocator, // this shouldnt need to allocate
            sysvar.EpochRewards,
            &buffer,
            .{},
        );
        try std.testing.expectEqual(obj_parsed, src.rewards);
        try std.testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&src.fill(true, obj_parsed)),
            std.mem.asBytes(&clean_obj),
        );
    }

    // Test last restart slot sysvar
    {
        var obj = sysvar.LastRestartSlot.INIT;
        const obj_addr = 0x100000000;

        var buffer = std.mem.zeroes([sysvar.LastRestartSlot.STORAGE_SIZE]u8);
        const buffer_addr = 0x200000000;
        const id_addr = 0x300000000;

        var clean_obj = src.fill(true, obj); // has bytes/padding zeroed.
        clean_obj.last_restart_slot = src.restart.last_restart_slot;

        var memory_map = try MemoryMap.init(
            allocator,
            &.{
                memory.Region.init(.mutable, std.mem.asBytes(&obj), obj_addr),
                memory.Region.init(.mutable, &buffer, buffer_addr),
                memory.Region.init(.constant, &sysvar.LastRestartSlot.ID.data, id_addr),
            },
            .v3,
            .{},
        );
        defer memory_map.deinit(allocator);

        try callSysvarSyscall(&tc, &memory_map, getLastRestartSlot, .{obj_addr});
        try std.testing.expectEqual(obj, src.restart);
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&obj), std.mem.asBytes(&clean_obj));

        try callSysvarSyscall(&tc, &memory_map, getSysvar, .{
            id_addr,
            buffer_addr,
            0,
            sysvar.LastRestartSlot.STORAGE_SIZE,
        });
        const obj_parsed = try bincode.readFromSlice(
            std.testing.allocator, // this shouldnt need to allocate
            sysvar.LastRestartSlot,
            &buffer,
            .{},
        );
        try std.testing.expectEqual(obj_parsed, src.restart);
        try std.testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&src.fill(true, obj_parsed)),
            std.mem.asBytes(&clean_obj),
        );
    }
}

test "getSysvar(StakeHistory, partial)" {
    try testGetStakeHistory(false);
}

test "getSysvar(StakeHistory, full)" {
    try testGetStakeHistory(true);
}

fn testGetStakeHistory(filled: bool) !void {
    const allocator = std.testing.allocator;
    const epochs: u64 = if (filled)
        sysvar.StakeHistory.MAX_ENTRIES + 1
    else
        sysvar.StakeHistory.MAX_ENTRIES / 2;

    var entries: std.BoundedArray(
        sysvar.StakeHistory.Entry,
        sysvar.StakeHistory.MAX_ENTRIES,
    ) = .{};
    for (1..epochs) |epoch| {
        try entries.append(.{ .epoch = epoch, .stake = .{
            .effective = epoch * 2,
            .activating = epoch * 3,
            .deactivating = epoch * 5,
        } });
    }

    const src_history = sysvar.StakeHistory.initWithEntries(entries.constSlice());
    // deinitialised by transaction context

    {
        const src_history_buf = try allocator.alloc(u8, sysvar.StakeHistory.STORAGE_SIZE);
        defer allocator.free(src_history_buf);
        _ = try bincode.writeToSlice(src_history_buf, src_history, .{});
    }

    const testing = sig.runtime.testing;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{},
        .compute_meter = std.math.maxInt(u64),
        .sysvar_cache = .{ .stake_history = src_history },
    });
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    var buffer = std.mem.zeroes([sysvar.StakeHistory.STORAGE_SIZE]u8);
    const buffer_addr = 0x100000000;
    const id_addr = 0x200000000;

    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.mutable, &buffer, buffer_addr),
            memory.Region.init(.constant, &sysvar.StakeHistory.ID.data, id_addr),
        },
        .v3,
        .{},
    );
    defer memory_map.deinit(allocator);

    try callSysvarSyscall(&tc, &memory_map, getSysvar, .{
        id_addr,
        buffer_addr,
        0,
        sysvar.StakeHistory.STORAGE_SIZE,
    });

    const obj_parsed = try bincode.readFromSlice(allocator, sysvar.StakeHistory, &buffer, .{});

    try std.testing.expectEqualSlices(
        sysvar.StakeHistory.Entry,
        obj_parsed.entries.constSlice(),
        src_history.entries.constSlice(),
    );
}

test "getSysvar(SlotHashes, partial)" {
    try testGetSlotHashes(false);
}

test "getSysvar(SlotHashes, full)" {
    try testGetSlotHashes(true);
}

fn testGetSlotHashes(filled: bool) !void {
    const allocator = std.testing.allocator;
    const slots: u64 = if (filled)
        sysvar.SlotHashes.MAX_ENTRIES + 1
    else
        sysvar.SlotHashes.MAX_ENTRIES / 2;

    var entries: std.BoundedArray(
        sysvar.SlotHashes.Entry,
        sysvar.SlotHashes.MAX_ENTRIES,
    ) = .{};
    for (1..slots) |slot| {
        var result: Hash = undefined;
        std.crypto.hash.sha2.Sha256.hash(std.mem.asBytes(&@as(u64, slot)), &result.data, .{});
        try entries.append(.{ .slot = slot, .hash = result });
    }

    const src_hashes = sysvar.SlotHashes.initWithEntries(entries.constSlice());
    // deinitialised by transaction context

    {
        const src_hashes_buf = try allocator.alloc(u8, sysvar.SlotHashes.STORAGE_SIZE);
        defer allocator.free(src_hashes_buf);
        _ = try bincode.writeToSlice(src_hashes_buf, src_hashes, .{});
    }

    const testing = sig.runtime.testing;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{},
        .compute_meter = std.math.maxInt(u64),
        .sysvar_cache = .{ .slot_hashes = src_hashes },
    });
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    var buffer = std.mem.zeroes([sysvar.SlotHashes.STORAGE_SIZE]u8);
    const buffer_addr = 0x100000000;
    const id_addr = 0x200000000;

    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.mutable, &buffer, buffer_addr),
            memory.Region.init(.constant, &sysvar.SlotHashes.ID.data, id_addr),
        },
        .v3,
        .{},
    );
    defer memory_map.deinit(allocator);

    try callSysvarSyscall(&tc, &memory_map, getSysvar, .{
        id_addr,
        buffer_addr,
        0,
        sysvar.SlotHashes.STORAGE_SIZE,
    });

    const obj_parsed = try bincode.readFromSlice(allocator, sysvar.SlotHashes, &buffer, .{});

    try std.testing.expectEqualSlices(
        sysvar.SlotHashes.Entry,
        obj_parsed.entries.constSlice(),
        src_hashes.entries.constSlice(),
    );
}
