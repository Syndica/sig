const std = @import("std");
const sig = @import("../../../sig.zig");

const program = sig.runtime.program;

const Pubkey = sig.core.Pubkey;

const expectProgramExecuteResult = program.testing.expectProgramExecuteResult;
const expectProgramExecuteError = program.testing.expectProgramExecuteError;

const MAX_FILE_BYTES: usize = 1024 * 1024; // 1MiB

test "hello_world" {
    // pub fn process_instruction(
    //     _program_id: &Pubkey,
    //     _accounts: &[AccountInfo],
    //     _instruction_data: &[u8]
    // ) -> ProgramResult {
    //     msg!("Hello, world!");
    //     Ok(())
    // }

    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    const program_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        MAX_FILE_BYTES,
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
        .{},
    );
}

test "print_account" {
    // pub fn process_instruction(
    //     _program_id: &Pubkey,
    //     accounts: &[AccountInfo],
    //     _instruction_data: &[u8]
    // ) -> ProgramResult {
    //     msg!("account[0].pubkey: {}", accounts[0].key.to_string());
    //     msg!("account[0].lamports: {}", accounts[0].lamports());
    //     msg!("account[0].data: {:?}", accounts[0].data.borrow());
    //     msg!("account[0].owner: {}", accounts[0].owner.to_string());
    //     msg!("account[0].rent_epoch: {}", accounts[0].rent_epoch);
    //     msg!("account[0].is_signer: {}", accounts[0].is_signer);
    //     msg!("account[0].is_writable: {}", accounts[0].is_writable);
    //     msg!("account[0].executable: {}", accounts[0].executable);
    //     Ok(())
    // }

    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    const program_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "print_account.so",
        MAX_FILE_BYTES,
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
        .{},
    );
}

// Fails: Requires sol_alloc_free_ syscall
// [program source] https://github.com/solana-labs/solana-program-library/tree/master/shared-memory/program
test "fast_copy" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    const program_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "fast_copy.so",
        MAX_FILE_BYTES,
    );
    defer allocator.free(program_bytes);
    const program_account = .{
        .pubkey = program_id,
        .lamports = 1_000_000_000,
        .owner = program.bpf_loader_program.v3.ID,
        .executable = true,
        .rent_epoch = 0,
        .data = program_bytes,
    };

    const account_id = Pubkey.initRandom(prng.random());
    const initial_instruction_account = .{
        .pubkey = account_id,
        .owner = program_id,
        .data = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    const final_instruction_account = .{
        .pubkey = account_id,
        .owner = program_id,
        .data = &[_]u8{ 'm', 'y', ' ', 'd', 'a', 't', 'a', ' ', ':', ')' },
    };

    // First 8 bytes are the offset to write into the account data
    const instruction_data = [_]u8{
        0,   0,   0,   0,   0,   0,   0,   0,
        'm', 'y', ' ', 'd', 'a', 't', 'a', ' ',
        ':', ')',
    };

    try expectProgramExecuteResult(
        allocator,
        program_id,
        &instruction_data,
        &.{
            .{
                .index_in_transaction = 1,
                .is_signer = false,
                .is_writable = true,
            },
        },
        .{
            .accounts = &.{
                program_account,
                initial_instruction_account,
            },
            .compute_meter = 61,
        },
        .{
            .accounts = &.{
                program_account,
                final_instruction_account,
            },
        },
        .{},
    );
}

test "set_return_data" {
    // pub fn process_instruction(
    //     _program_id: &Pubkey,
    //     _accounts: &[AccountInfo],
    //     _instruction_data: &[u8]
    // ) -> ProgramResult {
    //     solana_program::program::set_return_data("Hello, world!".as_bytes());
    //     Ok(())
    // }

    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    const program_bytes = try readProgramBytes(
        allocator,
        sig.ELF_DATA_DIR ++ "set_return_data.so",
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
            .compute_meter = 141,
        },
        .{
            .accounts = accounts,
            .return_data = .{
                .program_id = program_id,
                .data = "Hello, world!",
            },
        },
        .{},
    );
}

test "program_is_not_executable" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    const program_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        MAX_FILE_BYTES,
    );
    defer allocator.free(program_bytes);

    const accounts = &.{
        .{
            .pubkey = program_id,
            .lamports = 1_000_000_000,
            .owner = program.bpf_loader_program.v3.ID,
            .executable = false,
            .rent_epoch = 0,
            .data = program_bytes,
        },
    };

    try expectProgramExecuteError(
        error.IncorrectProgramId,
        allocator,
        program_id,
        &[_]u8{},
        &.{},
        .{
            .accounts = accounts,
            .compute_meter = 137,
        },
        .{},
    );
}

test "program_invalid_account_data" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    var program_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        MAX_FILE_BYTES,
    );
    program_bytes[3] = 0x00; // corrupt the program
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

    const result = expectProgramExecuteResult(
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
        .{},
    );

    try std.testing.expectError(error.InvalidAccountData, result);
}

test "program_init_vm_not_enough_compute" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    const program_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        MAX_FILE_BYTES,
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

    var compute_budget = sig.runtime.ComputeBudget.default(1_400_000);
    // Set heap size so that heap cost is 8
    compute_budget.heap_size = 2 * 32 * 1024;

    const result = expectProgramExecuteResult(
        allocator,
        program_id,
        &[_]u8{},
        &.{},
        .{
            .accounts = accounts,
            .compute_meter = 7,
            .compute_budget = compute_budget,
        },
        .{},
        .{},
    );

    try std.testing.expectError(error.ProgramEnvironmentSetupFailure, result);
}
