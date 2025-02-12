const std = @import("std");

const SolBytes = extern struct {
    addr: [*]const u8,
    len: u64,
};

const log: *align(1) const fn (msg: [*]const u8, len: u64) void = @ptrFromInt(0x6bf5c3fe);

const sol_poseidon: *const fn (
    parameters: u64,
    endianness: u64,
    bytes: [*]const SolBytes,
    bytes_len: u64,
    result: [*]u8,
) void = @ptrFromInt(0xc4947c21);

const panic: *const fn ([*]const u8, u64, u64, u64) void = @ptrFromInt(0x686093bb);

const POSEIDON_PARAMETERS_BN254_X5 = 0;
const POSEIDON_ENDIANNESS_BIG_ENDIAN = 0;
const POSEIDON_RESULT_LENGTH = 32;

export fn entrypoint() u64 {
    {
        var result: [32]u8 = undefined;
        const expected: [32]u8 = .{
            13,  84, 225, 147, 143, 138, 140, 28,  125, 235, 94,
            3,   85, 242, 99,  25,  32,  123, 132, 254, 156, 162,
            206, 27, 38,  231, 53,  200, 41,  130, 25,  144,
        };

        const input1: [32]u8 = .{
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        };
        const input2: [32]u8 = .{
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        };

        const inputs: [2]SolBytes = .{
            .{ .addr = &input1, .len = 32 },
            .{ .addr = &input2, .len = 32 },
        };

        sol_poseidon(
            POSEIDON_PARAMETERS_BN254_X5,
            POSEIDON_ENDIANNESS_BIG_ENDIAN,
            &inputs,
            2,
            &result,
        );

        if (!std.mem.eql(u8, &result, &expected)) panic("failed", 6, 0, 0);
    }

    return 0;
}
