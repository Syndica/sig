const set_return_data: *align(1) const fn ([*]const u8, usize) void = @ptrFromInt(0xa226d3eb);

export fn entrypoint(_: [*]u8, instruction_data_addr: [*]const u8) u64 {
    const instruction_data_len = @as([*]align(1) const u64, @ptrCast(instruction_data_addr - 8))[0];
    const instruction_data = instruction_data_addr[0..instruction_data_len];

    set_return_data(instruction_data.ptr, instruction_data.len);

    return 0;
}
