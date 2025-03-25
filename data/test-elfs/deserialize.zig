const sdk = @import("sdk");

export fn entrypoint(input: [*]const u8) u32 {
    _ = sdk.deserialize(input);

    return 0;
}
