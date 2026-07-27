noinline fn function_stack_ref(stack: [*]u64) u64 {
    stack[0] += 1;
    return stack[0];
}

noinline fn function_sum(x: u64, y: u64) u64 {
    return x + y;
}

export fn entrypoint(x: *u8) u64 {
    var stack: [32]u64 = undefined;
    stack[0] = x.*;
    const y = function_stack_ref(&stack);
    const z = x.*;
    return function_sum(y, z);
}
