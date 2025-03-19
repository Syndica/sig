const std = @import("std");

const VAL_A: u64 = 41;
const VAL_B: u64 = 42;
const VAL_C: u64 = 43;

export fn entrypoint() u64 {
    asm volatile (""
        :
        : [val] "m" (&VAL_B),
        : "memory"
    );
    return @as(*const volatile u64, &VAL_B).*;
}
