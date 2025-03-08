const std = @import("std");

const SolBytes = extern struct {
    addr: [*]const u8,
    len: u64,
};

// hashed as `log`
const log: *align(1) const fn (msg: [*]const u8, len: u64) void = @ptrFromInt(0x6bf5c3fe);

// hashed as `sol_poseidon`
const sol_poseidon: *const fn (
    parameters: u64,
    endianness: u64,
    bytes: [*]const SolBytes,
    bytes_len: u64,
    result: [*]u8,
) void = @ptrFromInt(0xc4947c21);

// hashed as `panic`
const panic: *const fn ([*]const u8, u64, u64, u64) void = @ptrFromInt(0xb17b0490);

const POSEIDON_PARAMETERS_BN254_X5 = 0;
const POSEIDON_ENDIANNESS_BIG_ENDIAN = 0;
const POSEIDON_ENDIANNESS_LITTLE_ENDIAN = 1;

/// Mirrors this Agave test: https://github.com/anza-xyz/agave/blob/e87917adab5468fe13287147800922a3191d0040/programs/sbf/c/src/poseidon/poseidon.c#L8
export fn entrypoint() u64 {
    // Two inputs: ones and twos (big-endian).
    {
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

        const expected: [32]u8 = .{
            13,  84, 225, 147, 143, 138, 140, 28,  125, 235, 94,
            3,   85, 242, 99,  25,  32,  123, 132, 254, 156, 162,
            206, 27, 38,  231, 53,  200, 41,  130, 25,  144,
        };

        expectEqual(&inputs, &expected, .big);
    }
    // Two inputs: ones and twos (little-endian).
    {
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

        const expected: [32]u8 = .{
            144, 25,  130, 41,  200, 53,  231, 38,  27, 206, 162,
            156, 254, 132, 123, 32,  25,  99,  242, 85, 3,   94,
            235, 125, 28,  140, 138, 143, 147, 225, 84, 13,
        };

        expectEqual(&inputs, &expected, .little);
    }

    const input0: [32]u8 = .{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    };

    // 1 input.
    {
        const expected: [32]u8 = .{
            41,  23,  97,  0,   234, 169, 98,  189, 193, 254, 108,
            101, 77,  106, 60,  19,  14,  150, 164, 209, 22,  139,
            51,  132, 139, 137, 125, 197, 2,   130, 1,   51,
        };
        const inputs: [1]SolBytes = .{
            .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 2 inputs.
    {
        const expected: [32]u8 = .{
            0,   122, 243, 70,  226, 211, 4,   39,  158, 121, 224,
            169, 243, 2,   63,  119, 18,  148, 167, 138, 203, 112,
            231, 63,  144, 175, 226, 124, 173, 64,  30,  129,
        };
        const inputs: [2]SolBytes = .{
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 3 inputs.
    {
        const expected: [32]u8 = .{
            2,   192, 6,   110, 16,  167, 42,  189, 43,  51, 195,
            178, 20,  203, 62,  129, 188, 177, 182, 227, 9,  97,
            205, 35,  194, 2,   177, 134, 115, 191, 37,  67,
        };
        const inputs: [3]SolBytes = .{
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 4 inputs.
    {
        const expected: [32]u8 = .{
            8,   44,  156, 55,  10,  13,  36, 244, 65,  111, 188,
            65,  74,  55,  104, 31,  120, 68, 45,  39,  216, 99,
            133, 153, 28,  23,  214, 252, 12, 75,  125, 113,
        };
        const inputs: [4]SolBytes = .{
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 5 inputs.
    {
        const expected: [32]u8 = .{
            16,  56,  150, 5,   174, 104, 141, 79,  20,  219, 133,
            49,  34,  196, 125, 102, 168, 3,   199, 43,  65,  88,
            156, 177, 191, 134, 135, 65,  178, 6,   185, 187,
        };
        const inputs: [5]SolBytes = .{
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 6 inputs.
    {
        const expected: [32]u8 = .{
            42,  115, 246, 121, 50,  140, 62,  171, 114, 74,  163,
            229, 189, 191, 80,  179, 144, 53,  215, 114, 159, 19,
            91,  151, 9,   137, 15,  133, 197, 220, 94,  118,
        };
        const inputs: [6]SolBytes = .{
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 7 inputs.
    {
        const expected: [32]u8 = .{
            34,  118, 49,  10,  167, 243, 52,  58, 40,  66,  20,
            19,  157, 157, 169, 89,  190, 42,  49, 178, 199, 8,
            165, 248, 25,  84,  178, 101, 229, 58, 48,  184,
        };
        const inputs: [7]SolBytes = .{
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 8 inputs.
    {
        const expected: [32]u8 = .{
            23, 126, 20,  83, 196, 70, 225, 176, 125, 43,  66,
            51, 66,  81,  71, 9,   92, 79,  202, 187, 35,  61,
            35, 11,  109, 70, 162, 20, 217, 91,  40,  132,
        };
        const inputs: [8]SolBytes = .{
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 9 inputs.
    {
        const expected: [32]u8 = .{
            14,  143, 238, 47, 228, 157, 163, 15,  222, 235, 72,
            196, 46,  187, 68, 204, 110, 231, 5,   95,  97,  251,
            202, 94,  49,  59, 138, 95,  202, 131, 76,  71,
        };
        const inputs: [9]SolBytes = .{
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 10 inputs.
    {
        const expected: [32]u8 = .{
            46,  196, 198, 94,  99,  120, 171, 140, 115, 48,  133,
            79,  74,  112, 119, 193, 255, 146, 96,  228, 72,  133,
            196, 184, 29,  209, 49,  173, 58,  134, 205, 150,
        };
        const inputs: [10]SolBytes = .{
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 11 inputs.
    {
        const expected: [32]u8 = .{
            0,   113, 61,  65, 236, 166, 53,  241, 23,  212, 236,
            188, 235, 95,  58, 102, 220, 65,  66,  235, 112, 181,
            103, 101, 188, 53, 143, 27,  236, 64,  187, 155,
        };
        const inputs: [11]SolBytes = .{
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }
    // 12 inputs.
    {
        const expected: [32]u8 = .{
            20,  57,  11,  224, 186, 239, 36,  155, 212, 124, 101,
            221, 172, 101, 194, 229, 46,  133, 19,  192, 129, 193,
            205, 114, 201, 128, 6,   9,   142, 154, 143, 190,
        };
        const inputs: [12]SolBytes = .{
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
            .{ .addr = &input0, .len = 32 }, .{ .addr = &input0, .len = 32 },
        };
        expectEqual(&inputs, &expected, .big);
    }

    return 0;
}

fn expectEqual(
    inputs: []const SolBytes,
    expected: []const u8,
    endian: std.builtin.Endian,
) void {
    var result: [32]u8 = undefined;
    sol_poseidon(
        POSEIDON_PARAMETERS_BN254_X5,
        switch (endian) {
            .big => POSEIDON_ENDIANNESS_BIG_ENDIAN,
            .little => POSEIDON_ENDIANNESS_LITTLE_ENDIAN,
        },
        inputs.ptr,
        inputs.len,
        &result,
    );
    if (!std.mem.eql(u8, &result, expected)) {
        log(&result, 32);
        panic("failed", 6, 0, 0);
    }
}
