const std = @import("std");
const sig = @import("../../sig.zig");
const Pubkey = sig.core.Pubkey;
const Instruction = sig.core.Instruction;

pub const ID: Pubkey = .parse("Sysvar1nstructions1111111111111111111111111");

// [agave] https://github.com/anza-xyz/solana-sdk/blob/0fbfb7d1467c1ab0c35e1a3b905b8ba0ac0bf538/instructions-sysvar/src/lib.rs#L77
pub const InstructionsSysvarAccountMeta = packed struct(u8) {
    is_signer: bool,
    is_writable: bool,
    _: u6 = 0, // padding
};

// [agave] https://github.com/anza-xyz/solana-sdk/blob/0fbfb7d1467c1ab0c35e1a3b905b8ba0ac0bf538/instructions-sysvar/src/lib.rs#L99
// First encode the number of instructions:
// [0..2 - num_instructions
//
// Then a table of offsets of where to find them in the data
//  3..2 * num_instructions table of instruction offsets
//
// Each instruction is then encoded as:
//   0..2 - num_accounts
//   2 - meta_byte -> (bit 0 signer, bit 1 is_writable)
//   3..35 - pubkey - 32 bytes
//   35..67 - program_id
//   67..69 - data len - u16
//   69..data_len - data
pub fn serializeInstructions(
    allocator: std.mem.Allocator,
    instructions: []const Instruction,
) !std.array_list.Managed(u8) {
    if (instructions.len > std.math.maxInt(u16)) unreachable;

    const asBytes = std.mem.asBytes;
    const nativeToLittle = std.mem.nativeToLittle;

    // estimated required capacity
    var data = try std.array_list.Managed(u8).initCapacity(allocator, instructions.len * 64);
    errdefer data.deinit();

    try data.appendSlice(asBytes(&nativeToLittle(u16, @intCast(instructions.len))));
    for (0..instructions.len) |_| try data.appendSlice(&.{ 0, 0 });

    for (instructions, 0..) |instruction, i| {
        const start_instruction_offset: u16 = @intCast(data.items.len);
        const start = 2 + (2 * i);
        @memcpy(
            data.items[start .. start + 2],
            asBytes(&nativeToLittle(u16, start_instruction_offset)),
        );
        try data.appendSlice(asBytes(&nativeToLittle(u16, @intCast(instruction.accounts.len))));

        for (instruction.accounts) |account_meta| {
            const flags: InstructionsSysvarAccountMeta = .{
                .is_signer = account_meta.is_signer,
                .is_writable = account_meta.is_writable,
            };
            try data.append(@bitCast(flags));
            try data.appendSlice(&account_meta.pubkey.data);
        }

        try data.appendSlice(&instruction.program_id.data);
        try data.appendSlice(asBytes(&nativeToLittle(u16, @intCast(instruction.data.len))));
        try data.appendSlice(instruction.data);
    }

    return data;
}

// (does not test deserialisation - not implemented yet)
// [agave] https://github.com/anza-xyz/agave/blob/a00f1b5cdea9a7d5a70f8d24b86ea3ae66feff11/sdk/program/src/sysvar/instructions.rs#L520
test serializeInstructions {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_id0 = Pubkey.initRandom(prng.random());
    const program_id1 = Pubkey.initRandom(prng.random());
    const id0 = Pubkey.initRandom(prng.random());
    const id1 = Pubkey.initRandom(prng.random());
    const id2 = Pubkey.initRandom(prng.random());
    const id3 = Pubkey.initRandom(prng.random());

    const instructions = [_]Instruction{
        .{
            .program_id = program_id0,
            .accounts = &.{
                .{ .pubkey = id0, .is_signer = false, .is_writable = false },
            },
            .data = &.{0},
            .owned_data = false,
        },
        .{
            .program_id = program_id0,
            .accounts = &.{
                .{ .pubkey = id1, .is_signer = true, .is_writable = false },
            },
            .data = &.{0},
            .owned_data = false,
        },
        .{
            .program_id = program_id1,
            .accounts = &.{
                .{ .pubkey = id2, .is_signer = false, .is_writable = true },
            },
            .data = &.{0},
            .owned_data = false,
        },
        .{
            .program_id = program_id1,
            .accounts = &.{
                .{ .pubkey = id3, .is_signer = true, .is_writable = true },
            },
            .data = &.{0},
            .owned_data = false,
        },
    };

    const serialized = try serializeInstructions(allocator, &instructions);
    defer serialized.deinit();
}
