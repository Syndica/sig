export fn foo() void {}
export fn entrypoint() u64 {
    foo();
    return 10;
}
