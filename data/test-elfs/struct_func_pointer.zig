const PubkeyLutEntry = extern struct {
    fp: *const fn (u8) callconv(.C) u8,
    key: u64,
};

fn f1(a: u8) callconv(.C) u8 {
    return a + 1;
}

export const entry: PubkeyLutEntry linksection(".data.rel.ro") = .{
    .fp = f1,
    .key = 0x0102030405060708,
};

export fn entrypoint() u64 {
    return entry.key;
}
