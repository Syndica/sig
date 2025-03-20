const sdk = @import("sdk");

const log = sdk.defineSyscall("log");

export fn entrypoint() u64 {
    log("foo\n", 4);
    return 0;
}
