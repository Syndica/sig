extern fn log(msg: [*]const u8, len: u64) void;

export fn entrypoint() u64 {
    log("foo\n", 4);
    return 0;
}
