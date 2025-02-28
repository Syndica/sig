const log: *align(1) const fn (msg: [*]const u8, len: u64) void =
    // the murmur hash for "log"
    @ptrFromInt(0x6bf5c3fe);

export fn entrypoint() u64 {
    log("foo\n", 4);
    return 0;
}
