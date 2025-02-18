const std = @import("std");

const VAL: u64 = 42;

noinline fn foo(ptr: *const volatile u64) u64 {
    return ptr.*;
}

export fn entrypoint() u64 {
    return foo(&VAL);
}
