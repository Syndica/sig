const sol_log_: *align(1) const fn (msg: [*]const u8, len: u64) void =
    // the murmur hash for "sol_log_"
    @ptrFromInt(0x207559bd);

export fn entrypoint() u64 {
    sol_log_("foo\n", 4);
    return 0;
}
