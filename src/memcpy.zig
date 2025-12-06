// https://github.com/facebook/folly/blob/1c8bc50e88804e2a7361a57cd9b551dd10f6c5fd/folly/memcpy.S
export fn memcpy(maybe_dest: ?[*]u8, maybe_src: ?[*]const u8, len: usize) callconv(.C) ?[*]u8 {
    @disableIntrinsics();

    if (len == 0) {
        @branchHint(.unlikely);
        return maybe_dest;
    }

    const dest = maybe_dest.?;
    const src = maybe_src.?;

    if (len < 8) {
        @branchHint(.unlikely);
        if (len == 1) {
            @branchHint(.unlikely);
            dest[0] = src[0];
        } else if (len >= 4) {
            @branchHint(.unlikely);
            blockCopy(dest, src, 4, len);
        } else {
            blockCopy(dest, src, 2, len);
        }
        return dest;
    }

    if (len > 32) {
        @branchHint(.unlikely);
        if (len > 256) {
            @branchHint(.unlikely);
            copyMove(dest, src, len);
            return dest;
        }
        copyLong(dest, src, len);
        return dest;
    }

    if (len > 16) {
        @branchHint(.unlikely);
        blockCopy(dest, src, 16, len);
        return dest;
    }

    blockCopy(dest, src, 8, len);

    return dest;
}

inline fn blockCopy(dest: [*]u8, src: [*]const u8, block_size: comptime_int, len: usize) void {
    const first: @Vector(block_size, u8) = src[0..block_size].*;
    const second: @Vector(block_size, u8) = src[len - block_size ..][0..block_size].*;
    dest[0..block_size].* = first;
    dest[len - block_size ..][0..block_size].* = second;
}

inline fn copyLong(dest: [*]u8, src: [*]const u8, len: usize) void {
    var array: [8]@Vector(32, u8) = undefined;

    inline for (.{ 64, 128, 192, 256 }, 0..) |N, i| {
        array[i * 2] = src[(N / 2) - 32 ..][0..32].*;
        array[(i * 2) + 1] = src[len - N / 2 ..][0..32].*;

        if (len <= N) {
            @branchHint(.unlikely);
            for (0..i + 1) |j| {
                dest[j * 32 ..][0..32].* = array[j * 2];
                dest[len - ((j * 32) + 32) ..][0..32].* = array[(j * 2) + 1];
            }
            return;
        }
    }
}

inline fn copyMove(dest: [*]u8, src: [*]const u8, len: usize) void {
    if (@intFromPtr(src) >= @intFromPtr(dest)) {
        @branchHint(.unlikely);
        copyForward(dest, src, len);
    } else if (@intFromPtr(src) + len > @intFromPtr(dest)) {
        @branchHint(.unlikely);
        overlapBwd(dest, src, len);
    } else {
        copyForward(dest, src, len);
    }
}

inline fn copyForward(dest: [*]u8, src: [*]const u8, len: usize) void {
    const tail: @Vector(32, u8) = src[len - 32 ..][0..32].*;

    const N: usize = len & ~@as(usize, 127);
    var i: usize = 0;

    while (i < N) : (i += 128) {
        dest[i..][0..32].* = src[i..][0..32].*;
        dest[i + 32 ..][0..32].* = src[i + 32 ..][0..32].*;
        dest[i + 64 ..][0..32].* = src[i + 64 ..][0..32].*;
        dest[i + 96 ..][0..32].* = src[i + 96 ..][0..32].*;
    }

    if (len - i <= 32) {
        @branchHint(.unlikely);
        dest[len - 32 ..][0..32].* = tail;
    } else {
        copyLong(dest[i..], src[i..], len - i);
    }
}

inline fn overlapBwd(dest: [*]u8, src: [*]const u8, len: usize) void {
    var array: [5]@Vector(32, u8) = undefined;
    array[0] = src[len - 32 ..][0..32].*;
    inline for (1..5) |i| array[i] = src[(i - 1) << 5 ..][0..32].*;

    const end: usize = (@intFromPtr(dest) + len - 32) & 31;
    const range = len - end;
    var s = src + range;
    var d = dest + range;

    while (@intFromPtr(s) > @intFromPtr(src + 128)) {
        // zig fmt: off
        const first:  @Vector(32, u8) = (s - 32) [0..32].*;
        const second: @Vector(32, u8) = (s - 64) [0..32].*;
        const third:  @Vector(32, u8) = (s - 96) [0..32].*;
        const fourth: @Vector(32, u8) = (s - 128)[0..32].*;

        (d - 32) [0..32].*  = first;
        (d - 64) [0..32].*  = second;
        (d - 96) [0..32].*  = third;
        (d - 128)[0..32].*  = fourth;
        // zig fmt: on

        s -= 128;
        d -= 128;
    }

    inline for (array[1..], 0..) |vec, i| dest[i * 32 ..][0..32].* = vec;
    dest[len - 32 ..][0..32].* = array[0];
}
