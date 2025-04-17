const std = @import("std");

/// hashed as `sol_memcpy_`
const memcpy: *align(1) const fn (
    dst: [*]u8,
    src: [*]const u8,
    len: usize,
) void = @ptrFromInt(0x717cc4a3);

// hashed as `sol_log_`
const log: *align(1) const fn (msg: [*]const u8, len: u64) void = @ptrFromInt(0x207559BD);

const Pubkey = extern struct {
    hash: [32]u8,
};

const AccountInfo = extern struct {
    key: *Pubkey,
    lamports: *u64,
    data_len: u64,
    data: [*]u8,
    owner: *Pubkey,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
};

const Params = extern struct {
    ka: [1]AccountInfo,
    data: [*]u8,
    data_len: u64,
    program_id: *Pubkey,
};

fn sol_deserialize(input_ptr: [*]u8) Params {
    var input: [*]u8 = input_ptr;

    const num_accounts = std.mem.readInt(u64, input[0..8], .little);
    input += 8;

    var params: Params = undefined;

    for (0..num_accounts) |i| {
        const info = input[0];
        input += 1;

        if (info == std.math.maxInt(u8)) {
            params.ka[i].is_signer = input[0] != 0;
            input += @sizeOf(u8);

            params.ka[i].is_writable = input[0] != 0;
            input += @sizeOf(u8);

            params.ka[i].is_writable = input[0] != 0;
            input += @sizeOf(u8);

            input += 4;

            params.ka[i].key = @ptrCast(input);
            input += @sizeOf(Pubkey);

            params.ka[i].owner = @ptrCast(input);
            input += @sizeOf(Pubkey);

            params.ka[i].lamports = @alignCast(@ptrCast(input));
            input += @sizeOf(u64);

            params.ka[i].data_len = std.mem.readInt(u64, input[0..8], .little);
            input += @sizeOf(u64);

            params.ka[i].data = input;
            input += params.ka[i].data_len;

            // TODO: there's more to this deserialize function, but we don't use
            // anymore in this test case
        }
    }

    return params;
}

export fn entrypoint(input: [*]u8) i32 {
    const info = sol_deserialize(input);
    memcpy(info.ka[0].data, &.{ 10, 20, 30 }, info.ka[0].data_len);
    return 0;
}
