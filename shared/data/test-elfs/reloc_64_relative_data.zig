const DATA = "hello";

export fn entrypoint() u64 {
    return @intFromPtr(&DATA);
}
