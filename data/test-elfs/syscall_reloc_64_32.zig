extern fn sol_log_(msg: [*]const u8, len: u64) void;

export fn entrypoint() u64 {
    sol_log_("foo\n", 4);
    return 0;
}
