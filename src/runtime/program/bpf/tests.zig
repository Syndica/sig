const std = @import("std");
const sig = @import("../../../sig.zig");

const sbpf = sig.vm.sbpf;
const program = sig.runtime.program;

const Pubkey = sig.core.Pubkey;
const LogCollector = sig.runtime.LogCollector;

const expectProgramExecuteResult = program.testing.expectProgramExecuteResult;

test "hello_world" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    const program_bytes = try readProgramBytes(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
    );
    defer allocator.free(program_bytes);

    const accounts = &.{
        .{
            .pubkey = program_id,
            .lamports = 1_000_000_000,
            .owner = program.bpf_loader_program.v3.ID,
            .executable = true,
            .rent_epoch = 0,
            .data = program_bytes,
        },
    };

    try expectProgramExecuteResult(
        allocator,
        program_id,
        &[_]u8{},
        &.{},
        .{
            .accounts = accounts,
            .compute_meter = 137,
        },
        .{
            .accounts = accounts,
        },
        .{
            .print_logs = true,
        },
    );
}

test "print_account" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    const program_bytes = try readProgramBytes(
        allocator,
        sig.ELF_DATA_DIR ++ "print_account.so",
    );
    defer allocator.free(program_bytes);

    const accounts = &.{
        .{
            .pubkey = program_id,
            .lamports = 1_000_000_000,
            .owner = program.bpf_loader_program.v3.ID,
            .executable = true,
            .rent_epoch = 0,
            .data = program_bytes,
        },
        .{
            .pubkey = Pubkey.initRandom(prng.random()),
            .lamports = 1_234_456,
            .owner = Pubkey.initRandom(prng.random()),
            .executable = false,
            .rent_epoch = 25,
            .data = &[_]u8{ 'm', 'y', ' ', 'd', 'a', 't', 'a', ' ', ':', ')' },
        },
    };

    try expectProgramExecuteResult(
        allocator,
        program_id,
        &[_]u8{},
        &.{
            .{
                .index_in_transaction = 1,
                .is_signer = false,
                .is_writable = false,
            },
        },
        .{
            .accounts = accounts,
            .compute_meter = 29_105,
        },
        .{
            .accounts = accounts,
        },
        .{
            .print_logs = true,
        },
    );
}

fn readProgramBytes(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const input_file = try std.fs.cwd().openFile(path, .{});
    return try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
}
