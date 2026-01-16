const std = @import("std");
const sig = @import("../../../sig.zig");

const program_loader = sig.runtime.program_loader;
const vm = sig.vm;

const program = sig.runtime.program;
const Pubkey = sig.core.Pubkey;
const ExecuteContextParams = sig.runtime.testing.ExecuteContextsParams;
const AccountParams = ExecuteContextParams.AccountParams;
const AccountSharedData = sig.runtime.AccountSharedData;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const ComputeBudget = sig.runtime.ComputeBudget;
const FeatureParams = sig.runtime.testing.ExecuteContextsParams.FeatureParams;

const expectProgramExecuteResult = program.testing.expectProgramExecuteResult;
const expectProgramExecuteError = program.testing.expectProgramExecuteError;

const MAX_FILE_BYTES: usize = 1024 * 1024; // 1MiB

pub fn prepareBpfV3Test(
    allocator: std.mem.Allocator,
    random: std.Random,
    elf_bytes: []const u8,
    feature_params: []const FeatureParams,
) !struct { AccountParams, vm.Environment, *ProgramMap } {
    const program_key = Pubkey.initRandom(random);
    const program_data_key = Pubkey.initRandom(random);
    const program_deployment_slot = random.int(u64) -| 1;
    const program_update_authority = null;

    const feature_set = try sig.runtime.testing.createFeatureSet(feature_params);
    var accounts: sig.utils.collections.PubkeyMap(AccountSharedData) = .{};
    defer {
        for (accounts.values()) |account| allocator.free(account.data);
        accounts.deinit(allocator);
    }

    const program_bytes, const program_data_bytes = try program_loader.createV3ProgramAccountData(
        allocator,
        program_data_key,
        program_deployment_slot,
        program_update_authority,
        elf_bytes,
    );

    try accounts.put(
        allocator,
        program_key,
        .{
            .lamports = 1,
            .owner = program.bpf_loader.v3.ID,
            .data = program_bytes,
            .executable = true,
            .rent_epoch = std.math.maxInt(u64),
        },
    );

    try accounts.put(
        allocator,
        program_data_key,
        .{
            .lamports = 1,
            .owner = program_key,
            .data = program_data_bytes,
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
        },
    );

    const program_account_params = AccountParams{
        .pubkey = program_key,
        .lamports = 1,
        .owner = program.bpf_loader.v3.ID,
        .data = try allocator.dupe(u8, program_bytes),
        .executable = true,
        .rent_epoch = std.math.maxInt(u64),
    };

    const compute_budget = ComputeBudget.DEFAULT;

    const environment = sig.vm.Environment.initV1(
        &feature_set,
        &compute_budget,
        0,
        false,
    );

    const program_map = try allocator.create(ProgramMap);
    errdefer allocator.destroy(program_map);

    program_map.* = try program_loader.testLoad(
        allocator,
        &accounts,
        &environment,
        program_deployment_slot + 1,
    );

    return .{ program_account_params, environment, program_map };
}

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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const elf_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        MAX_FILE_BYTES,
    );
    defer allocator.free(elf_bytes);

    const feature_params = &[_]FeatureParams{
        .{ .feature = .enable_sbpf_v3_deployment_and_execution },
    };

    const program_account, const environment, const program_map = try prepareBpfV3Test(
        allocator,
        prng.random(),
        elf_bytes,
        feature_params,
    );
    defer allocator.free(program_account.data);

    try expectProgramExecuteResult(
        allocator,
        program_account.pubkey.?,
        &[_]u8{},
        &.{},
        .{
            .accounts = &.{program_account},
            .compute_meter = 137,
            .program_map = program_map,
            .vm_environment = &environment,
            .feature_set = feature_params,
        },
        .{
            .accounts = &.{program_account},
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const elf_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "print_account.so",
        MAX_FILE_BYTES,
    );
    defer allocator.free(elf_bytes);

    const feature_params = &[_]FeatureParams{
        .{ .feature = .enable_sbpf_v3_deployment_and_execution },
    };

    const program_account, const environment, const program_map = try prepareBpfV3Test(
        allocator,
        prng.random(),
        elf_bytes,
        feature_params,
    );
    defer allocator.free(program_account.data);

    const accounts: []const AccountParams = &.{
        program_account,
        .{
            .pubkey = .parse("2W3R4CDyfdPBsABjBF86kdThsR5s89iX2wbfoGVhZw4M"),
            .lamports = 1_234_456,
            .owner = .parse("3DTD43NijdpuwzQL6fM19vU5hDZ2u6M7A9hMrJH3dJyD"),
            .executable = false,
            .rent_epoch = 25,
            .data = "my data :)",
        },
    };

    try expectProgramExecuteResult(
        allocator,
        program_account.pubkey.?,
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
            .compute_meter = 28_650,
            .program_map = program_map,
            .vm_environment = &environment,
            .feature_set = feature_params,
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const elf_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "fast_copy.so",
        MAX_FILE_BYTES,
    );
    defer allocator.free(elf_bytes);

    const feature_params = &[_]FeatureParams{
        .{ .feature = .enable_sbpf_v3_deployment_and_execution },
    };

    const program_account, const environment, const program_map = try prepareBpfV3Test(
        allocator,
        prng.random(),
        elf_bytes,
        feature_params,
    );
    defer allocator.free(program_account.data);

    const program_id = program_account.pubkey.?;
    const account_id = Pubkey.initRandom(prng.random());
    const initial_instruction_account: AccountParams = .{
        .pubkey = account_id,
        .owner = program_id,
        .data = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    const final_instruction_account: AccountParams = .{
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
            .program_map = program_map,
            .vm_environment = &environment,
            .feature_set = feature_params,
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const elf_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "set_return_data.so",
        MAX_FILE_BYTES,
    );
    defer allocator.free(elf_bytes);

    const feature_params = &[_]FeatureParams{
        .{ .feature = .enable_sbpf_v3_deployment_and_execution },
    };

    const program_account, const environment, const program_map = try prepareBpfV3Test(
        allocator,
        prng.random(),
        elf_bytes,
        feature_params,
    );
    defer allocator.free(program_account.data);

    try expectProgramExecuteResult(
        allocator,
        program_account.pubkey.?,
        &[_]u8{},
        &.{},
        .{
            .accounts = &.{program_account},
            .compute_meter = 141,
            .program_map = program_map,
            .vm_environment = &environment,
            .feature_set = feature_params,
        },
        .{
            .accounts = &.{program_account},
            .return_data = .{
                .program_id = program_account.pubkey.?,
                .data = "Hello, world!",
            },
        },
        .{},
    );
}

test "program_is_not_executable" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_id = Pubkey.initRandom(prng.random());
    const program_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        MAX_FILE_BYTES,
    );
    defer allocator.free(program_bytes);

    const accounts: []const AccountParams = &.{
        .{
            .pubkey = program_id,
            .lamports = 1_000_000_000,
            .owner = program.bpf_loader.v3.ID,
            .executable = false,
            .rent_epoch = 0,
            .data = program_bytes,
        },
    };

    try expectProgramExecuteError(
        error.UnsupportedProgramId,
        allocator,
        program_id,
        &[_]u8{},
        &.{},
        .{
            .accounts = accounts,
            .compute_meter = 137,
            .feature_set = &.{
                .{ .feature = .enable_sbpf_v3_deployment_and_execution },
            },
        },
        .{},
    );
}

test "program_unsupported_program_id" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_id = Pubkey.initRandom(prng.random());
    var program_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        MAX_FILE_BYTES,
    );
    program_bytes[3] = 0x00; // corrupt the program
    defer allocator.free(program_bytes);

    const accounts: []const AccountParams = &.{
        .{
            .pubkey = program_id,
            .lamports = 1_000_000_000,
            .owner = program.bpf_loader.v3.ID,
            .executable = true,
            .rent_epoch = 0,
            .data = program_bytes,
        },
    };

    try expectProgramExecuteError(
        error.UnsupportedProgramId,
        allocator,
        program_id,
        &[_]u8{},
        &.{},
        .{
            .accounts = accounts,
            .compute_meter = 137,
            .feature_set = &.{
                .{ .feature = .enable_sbpf_v3_deployment_and_execution },
            },
        },
        .{},
    );
}

test "program_init_vm_not_enough_compute" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const elf_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        MAX_FILE_BYTES,
    );
    defer allocator.free(elf_bytes);

    const feature_params = &[_]FeatureParams{
        .{ .feature = .enable_sbpf_v3_deployment_and_execution },
    };

    const program_account, const environment, const program_map = try prepareBpfV3Test(
        allocator,
        prng.random(),
        elf_bytes,
        feature_params,
    );
    defer allocator.free(program_account.data);

    var compute_budget = sig.runtime.ComputeBudget.DEFAULT;
    // Set heap size so that heap cost is 8
    compute_budget.heap_size = 2 * 32 * 1024;

    try expectProgramExecuteError(
        error.ProgramEnvironmentSetupFailure,
        allocator,
        program_account.pubkey.?,
        &[_]u8{},
        &.{},
        .{
            .accounts = &.{program_account},
            .compute_meter = 7,
            .program_map = program_map,
            .vm_environment = &environment,
            .compute_budget = compute_budget,
            .feature_set = feature_params,
        },
        .{},
    );
}
