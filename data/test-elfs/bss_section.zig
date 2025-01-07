// NOTE: the value is 0 in order to get the symbol into .bss
var x: u32 = 0;

export fn entrypoint() u32 {
    @as(*volatile u32, &x).* = 10;
    return 0;
}
