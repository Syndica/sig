var x: u32 = 42;

export fn entrypoint() u32 {
    @as(*volatile u32, &x).* = 10;
    return 0;
}
