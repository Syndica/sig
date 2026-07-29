const VAL_B: u64 = 42;

export fn entrypoint() u64 {
    asm volatile (""
        :
        : [val] "m" (&VAL_B),
        : .{ .memory = true });
    return @as(*const volatile u64, &VAL_B).*;
}
