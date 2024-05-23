//! Port of ChaCha from the `rand_chacha` crate.
//!
//! Generates the same psuedorandom numbers as rand_chacha, unlike Zig std's
//! ChaCha.
//!
//! This is needed since rand_chacha differs from the zig std's ChaCha in several
//! ways. One example is that it does not comply with the IETF standard, plus
//! there are other compatibility issues that require a different design from zig
//! std, like how it maintains state across iterations.

const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../lib.zig");

const mem = std.mem;

const BlockRng = sig.rand.BlockRng;

const endian = builtin.cpu.arch.endian();

/// A random number generator based on ChaCha.
/// Generates the same stream as ChaChaRng in `rand_chacha`.
/// This is an ease-of-use wrapper for the type:
///     BlockRng(ChaCha(rounds), ChaCha(rounds).generate)
pub fn ChaChaRng(comptime rounds: usize) type {
    return struct {
        block_rng: BlockRng(ChaCha(rounds), ChaCha(rounds).generate),

        const Self = @This();

        pub fn fromSeed(seed: [32]u8) Self {
            return .{ .block_rng = .{ .core = ChaCha(rounds).init(seed, .{0} ** 12) } };
        }

        pub fn random(self: *Self) std.rand.Random {
            return self.block_rng.random();
        }
    };
}

/// Computes the chacha stream.
///
/// This is the barebones implementation of the chacha stream cipher. If you're
/// looking for a random number generator based on the chacha stream cipher, use
/// ChaChaRng.
pub fn ChaCha(comptime rounds: usize) type {
    return struct {
        b: [4]u32,
        c: [4]u32,
        d: [4]u32,

        const Self = @This();

        pub fn init(key: [32]u8, nonce: [12]u8) Self {
            const ctr_nonce = .{0} ++ leIntBitCast([3]u32, nonce);
            return .{
                .b = leIntBitCast([4]u32, key[0..16].*),
                .c = leIntBitCast([4]u32, key[16..].*),
                .d = ctr_nonce,
            };
        }

        /// Run the full chacha algorithm, generating the next block of 64 32-bit
        /// integers.
        pub fn generate(self: *Self, out: *[64]u32) void {
            const k = comptime leIntBitCast([4]u32, @as([16]u8, "expand 32-byte k".*));
            const b = self.b;
            const c = self.c;
            var x = State{
                .a = .{ k, k, k, k },
                .b = .{ b, b, b, b },
                .c = .{ c, c, c, c },
                .d = repeat4timesAndAdd0123(self.d),
            };
            for (0..rounds / 2) |_| {
                x = diagonalize(round(diagonalize(round(x), 1)), -1);
            }
            const sb = self.b;
            const sc = self.c;
            const sd = repeat4timesAndAdd0123(self.d);
            const results: [64]u32 = @bitCast(transpose4(.{
                wrappingAddEachInt(x.a, .{ k, k, k, k }),
                wrappingAddEachInt(x.b, .{ sb, sb, sb, sb }),
                wrappingAddEachInt(x.c, .{ sc, sc, sc, sc }),
                wrappingAddEachInt(x.d, sd),
            }));
            @memcpy(out[0..64], &results);
            self.d = wrappingAddToFirstHalf(sd[0], 4);
        }
    };
}

const State = struct {
    a: [4][4]u32,
    b: [4][4]u32,
    c: [4][4]u32,
    d: [4][4]u32,

    const Self = @This();

    fn eql(self: *const Self, other: *const Self) bool {
        inline for (.{ "a", "b", "c", "d" }) |field_name| {
            const lhs = @field(self, field_name);
            const rhs = @field(other, field_name);
            for (0..4) |i| {
                if (!mem.eql(u32, &lhs[i], &rhs[i])) return false;
            }
        }
        return true;
    }
};

fn transpose4(a: [4][4][4]u32) [4][4][4]u32 {
    return .{
        .{ a[0][0], a[1][0], a[2][0], a[3][0] },
        .{ a[0][1], a[1][1], a[2][1], a[3][1] },
        .{ a[0][2], a[1][2], a[2][2], a[3][2] },
        .{ a[0][3], a[1][3], a[2][3], a[3][3] },
    };
}

/// converts the first two items into a u64 and then wrapping_adds the integer
/// `i` to it, then converts back to u32s.
fn wrappingAddToFirstHalf(d: [4]u32, i: u64) [4]u32 {
    var u64s = leIntBitCast([2]u64, d);
    u64s[0] += i;
    return leIntBitCast([4]u32, u64s);
}

fn repeat4timesAndAdd0123(d: [4]u32) [4][4]u32 {
    return .{
        wrappingAddToFirstHalf(d, 0),
        wrappingAddToFirstHalf(d, 1),
        wrappingAddToFirstHalf(d, 2),
        wrappingAddToFirstHalf(d, 3),
    };
}

/// Run a single round of the ChaCha algorithm
fn round(state: State) State {
    var x = state;
    x.a = wrappingAddEachInt(x.a, x.b);
    x.d = xorThenRotateRight(x.d, x.a, 16);
    x.c = wrappingAddEachInt(x.c, x.d);
    x.b = xorThenRotateRight(x.b, x.c, 20);
    x.a = wrappingAddEachInt(x.a, x.b);
    x.d = xorThenRotateRight(x.d, x.a, 24);
    x.c = wrappingAddEachInt(x.c, x.d);
    x.b = xorThenRotateRight(x.b, x.c, 25);
    return x;
}

fn wrappingAddEachInt(a: [4][4]u32, b: [4][4]u32) [4][4]u32 {
    var sum: [4][4]u32 = undefined;
    for (0..4) |i| for (0..4) |j| {
        sum[i][j] = a[i][j] +% b[i][j];
    };
    return sum;
}

fn xorThenRotateRight(const_lhs: [4][4]u32, rhs: [4][4]u32, rotate: anytype) [4][4]u32 {
    var lhs = const_lhs;
    for (0..4) |i| for (0..4) |j| {
        const xor = lhs[i][j] ^ rhs[i][j];
        lhs[i][j] = std.math.rotr(u32, xor, rotate);
    };
    return lhs;
}

/// Reinterprets an integer or array of integers as an integer or array of
/// integers with different sizes. For example, can convert u64 -> [2]u32 or vice
/// versa.
///
/// The function ensures that the resulting numbers are universal across
/// platforms, using little-endian ordering.
///
/// So, this is the same as @bitCast for little endian platforms, but it requires
/// a byte swap for big endian platforms.
fn leIntBitCast(comptime Output: type, input: anytype) Output {
    switch (endian) {
        .little => return @bitCast(input),
        .big => {
            if (numItems(Output) > numItems(@TypeOf(input))) {
                var in = input;
                for (&in) |*n| n.* = @byteSwap(n);
                return @bitCast(in);
            } else {
                var out: Output = @bitCast(input);
                for (&out) |*n| n.* = @byteSwap(n);
                return out;
            }
        },
    }
}

/// len of array, or 1 if not array.
fn numItems(comptime T: type) usize {
    return switch (@typeInfo(T)) {
        .Array => |a| a.len,
        else => 1,
    };
}

fn diagonalize(x: State, times: isize) State {
    var out: State = x;
    for (0..4) |i| {
        out.b[i] = rotateLeft(x.b[i], 1 * times);
        out.c[i] = rotateLeft(x.c[i], 2 * times);
        out.d[i] = rotateLeft(x.d[i], 3 * times);
    }
    return out;
}

/// Rotates array items to different locations in the array.
fn rotateLeft(item: [4]u32, n: isize) [4]u32 {
    return .{
        item[mod(n, 4)],
        item[mod((n + 1), 4)],
        item[mod((n + 2), 4)],
        item[mod((n + 3), 4)],
    };
}

fn mod(n: isize, len: usize) usize {
    return @intCast(std.math.mod(isize, n, @intCast(len)) catch unreachable);
}

test "Random.int(u32) works" {
    const chacha = ChaCha(20).init(.{0} ** 32, .{0} ** 12);
    var rng = BlockRng(ChaCha(20), ChaCha(20).generate){ .core = chacha };
    const random = rng.random();
    try std.testing.expect(2917185654 == random.int(u32));
}

test "Random.int(u64) works" {
    const chacha = ChaCha(20).init(.{0} ** 32, .{0} ** 12);
    var rng = BlockRng(ChaCha(20), ChaCha(20).generate){ .core = chacha };
    const random = rng.random();
    try std.testing.expect(10393729187455219830 == random.int(u64));
}

test "Random.bytes works" {
    const chacha = ChaCha(20).init(.{0} ** 32, .{0} ** 12);
    var rng = BlockRng(ChaCha(20), ChaCha(20).generate){ .core = chacha };
    const random = rng.random();
    var dest: [32]u8 = undefined;
    const midpoint = .{
        118, 184, 224, 173, 160, 241, 61,  144, 64,  93,  106, 229, 83, 134, 189, 40, 189, 210,
        25,  184, 160, 141, 237, 26,  168, 54,  239, 204, 139, 119, 13, 199,
    };
    random.bytes(&dest);
    try std.testing.expect(mem.eql(u8, &midpoint, &dest));
}

test "recursive fill" {
    var bytes: [32]u8 = .{0} ** 32;
    var rng_init = ChaChaRng(20).fromSeed(bytes);
    rng_init.random().bytes(&bytes);
    const chacha = ChaCha(20).init(bytes, .{0} ** 12);
    var rng = BlockRng(ChaCha(20), ChaCha(20).generate){ .core = chacha };
    rng.fill(&bytes);

    const expected = .{
        176, 253, 20,  255, 150, 160, 189, 161, 84,  195, 41,  8,  44, 156, 101, 51, 187,
        76,  148, 115, 191, 93,  222, 19,  143, 130, 201, 172, 85, 83, 217, 88,
    };
    try std.testing.expect(mem.eql(u8, &expected, &bytes));
}

test "dynamic next int works" {
    var bytes: [32]u8 = .{0} ** 32;
    var rng_init = ChaChaRng(20).fromSeed(bytes);
    rng_init.random().bytes(&bytes);
    const chacha = ChaCha(20).init(bytes, .{0} ** 12);
    var rng = BlockRng(ChaCha(20), ChaCha(20).generate){ .core = chacha };
    const u32s = [_]u32{
        4279565744, 862297132,  2898887311, 3678189893, 3874939098, 1553983382, 1031206440,
        978567423,  4209765794, 2063739027, 3497840189, 3042885724, 13559713,   2804739726,
        83427940,   1888646802, 2860787473, 1877744140, 3871387528, 2786522908, 315930854,
        120980593,  3002074910, 3285478202, 1586689760, 2340124627, 52115417,   2748045760,
        3357889967, 214072547,  1511164383, 1921839307, 842278728,  1023471299, 3744819639,
        4085269185, 3222055698, 1508829632, 3587328034, 451202787,  3647660313, 3102981063,
        3964799389, 3904121230, 2805919233, 2118987761, 3557954211, 3320127761, 2756534424,
        992375503,  3545628137, 1085584675, 1209223666, 2255867162, 1635202960, 2496462192,
        713473244,  1792112125, 3844522849, 2490299132, 4072683334, 70142460,   2095023485,
        461018663,  3859958840, 212748047,  2657724434, 81297974,   3942098154, 958741438,
        346419548,  2225828352, 2900251414, 336469631,  654063680,  1812174127, 609007208,
        846863059,  3189927372, 1905581022, 2172277675, 4037927613, 3495064163, 3874649746,
        3559563381, 590810202,  2664210773, 3223769241, 2040745611, 360514407,  2919944502,
        536370302,  1065703962, 7253915,    337567527,  1460887337, 1474807598, 1848190485,
        4096711861, 3404804800,
    };
    const u64s = [_]u64{
        588215994606788758,   1431684808409631931,  2931207493295625045,  3032891578644758194,
        418541299932196982,   15396241028896397909, 12835735727689995230, 9873538067654336105,
        12514793613430075092, 13232023512861211064, 16028062863378687135, 16967702477157236558,
        2887555945435226072,  17400462721248040447, 17117735807058458868, 15659305100245141846,
        2699089690138758189,  10755240647284155175, 1924095871294250220,  17515951820211362774,
        13373595865079936501, 6860971170011447095,  14703706923713349358, 11533069247885725721,
        3448216242831738015,  9278269248351279695,  9372255405263360037,  8707387524018776887,
        8746597495079144985,  7691371180483864508,  7537003725416187104,  1981019672903425841,
        10056652572362307735, 2436364459124478962,  2428925607328334081,  14712031039183662158,
        2614237173466617322,  4257610326057511672,  3540403114074859660,  6581767110215406295,
        15150451542146080734, 181278900145439701,   11760969932321600702, 17522913230875340068,
        10318893824576666810, 18312828410504980228, 2805875854392392082,  5355795946829941939,
        7515894275194643237,  9702265981800844421,  227603388627345368,   3324436570698804108,
        4753191896749056049,  17885086500265945805, 17435295308389799126, 5786986546027884036,
        17350667365223054483, 1154396925486892856,  5844933381342596954,  9570272635503767656,
        16336838788699700779, 2336639497643599348,  9795949699684750554,  6329973578295938791,
        15992525826554723486, 17793526484350803500, 13898491381782030824, 4397579918151967336,
        17917727240936500825, 7352683368508344350,  11766507471434633205, 9634720798753459106,
        16282012887761187213, 16324707443307008843, 14425283330535396682, 13172406095143567691,
        2691725161073047006,  1406030345077942778,  9684222056303881176,  9746143945091321583,
        8181709559804695063,  1654050647849141241,  18149780750595962095, 8493844361058276091,
        9446739672321797014,  12390809841934868939, 15188448811864282367, 98895932768533343,
        5024754166561341894,  9730267002865676284,  11893802928445802006, 18309480227270911117,
        17066717792185926269, 13499718013438346758, 5217404074882333630,  12694155839474838416,
        3008502677940577076,  11542601400063272771, 1730084963375478886,  1114921244491478328,
    };
    var random = rng.random();
    for (0..100) |i| {
        try std.testing.expect(u32s[i] == random.int(u32));
        try std.testing.expect(u64s[i] == random.int(u64));
    }
}

test "rng works" {
    const chacha = ChaCha(20).init(.{0} ** 32, .{0} ** 12);
    var rng = BlockRng(ChaCha(20), ChaCha(20).generate){ .core = chacha };
    var dest: [32]u8 = undefined;
    const midpoint = .{
        118, 184, 224, 173, 160, 241, 61,  144, 64,  93,  106, 229, 83, 134, 189, 40, 189, 210,
        25,  184, 160, 141, 237, 26,  168, 54,  239, 204, 139, 119, 13, 199,
    };
    rng.fill(&dest);
    // assert_eq!(midpoint, dest);
    try std.testing.expect(mem.eql(u8, &midpoint, &dest));
}

test "ChaCha works" {
    var chacha = ChaCha(20){
        .b = .{ 1, 2, 3, 4 },
        .c = .{ 5, 6, 7, 8 },
        .d = .{ 9, 10, 11, 12 },
    };
    var out: [64]u32 = .{0} ** 64;
    chacha.generate(&out);
    const expected1 = .{
        514454965,  2343183702, 485828088,  2392727011, 3682321578, 3166467596, 1535089427,
        266038024,  1861812015, 3818141583, 486852448,  277812666,  1961317633, 3870259557,
        3811097870, 10333140,   3471107314, 854767140,  1292362001, 1791493576, 684928595,
        2735203077, 3103536681, 1555264764, 2953779204, 1335099419, 3308039343, 3071159758,
        676902921,  3409736680, 289978712,  198159109,  4106483464, 4193260066, 389599996,
        1248502515, 607568078,  3047265466, 2254027974, 3837112036, 2647654845, 3933149571,
        251366014,  192741632,  4239604811, 2829206891, 2090618058, 86120867,   3489155609,
        162839505,  3738605468, 1369674854, 3501711964, 3507855056, 3021042483, 747171775,
        3095039326, 1302941762, 1534526601, 4269591531, 2416037718, 2139104272, 3631556128,
        4065100274,
    };
    try std.testing.expect(mem.eql(u32, &expected1, &out));
}

/// for testing
const test_start_state = State{
    .a = .{ .{ 0, 1, 2, 3 }, .{ 4, 5, 6, 7 }, .{ 8, 9, 10, 11 }, .{ 12, 13, 14, 15 } },
    .b = .{
        .{ 16, 17, 18, 19 },
        .{ 20, 21, 22, 23 },
        .{ 24, 25, 26, 27 },
        .{ 28, 29, 30, 31 },
    },
    .c = .{
        .{ 32, 33, 34, 35 },
        .{ 36, 37, 38, 39 },
        .{ 40, 41, 42, 43 },
        .{ 44, 45, 46, 47 },
    },
    .d = .{
        .{ 48, 49, 50, 51 },
        .{ 52, 53, 54, 55 },
        .{ 56, 57, 58, 59 },
        .{ 60, 61, 62, 63 },
    },
};

test "d0123 works" {
    const input = .{ 1, 2, 3, 4 };
    const expected_out: [4][4]u32 = .{
        .{ 1, 2, 3, 4 },
        .{ 2, 2, 3, 4 },
        .{ 3, 2, 3, 4 },
        .{ 4, 2, 3, 4 },
    };
    const output = repeat4timesAndAdd0123(input);
    for (0..4) |i| {
        try std.testing.expect(mem.eql(u32, &expected_out[i], &output[i]));
    }
}

test "diagonalize round trip" {
    const mid = diagonalize(test_start_state, 1);
    const expected_mid = State{
        .a = .{
            .{ 0, 1, 2, 3 },
            .{ 4, 5, 6, 7 },
            .{ 8, 9, 10, 11 },
            .{ 12, 13, 14, 15 },
        },
        .b = .{
            .{ 17, 18, 19, 16 },
            .{ 21, 22, 23, 20 },
            .{ 25, 26, 27, 24 },
            .{ 29, 30, 31, 28 },
        },
        .c = .{
            .{ 34, 35, 32, 33 },
            .{ 38, 39, 36, 37 },
            .{ 42, 43, 40, 41 },
            .{ 46, 47, 44, 45 },
        },
        .d = .{
            .{ 51, 48, 49, 50 },
            .{ 55, 52, 53, 54 },
            .{ 59, 56, 57, 58 },
            .{ 63, 60, 61, 62 },
        },
    };
    try std.testing.expect(expected_mid.eql(&mid));
    const end = diagonalize(mid, -1);
    try std.testing.expect(test_start_state.eql(&end));
}

test "round works" {
    const expected = State{
        .a = .{
            .{ 196626, 805502996, 1610809366, 1342373912 },
            .{ 3221422106, 4026728476, 2684551198, 2416115744 },
            .{ 2147680289, 2952986659, 3758293029, 3489857575 },
            .{ 1073938473, 1879244843, 537067565, 268632111 },
        },
        .b = .{
            .{ 2441679121, 269101448, 2458599458, 319568059 },
            .{ 2542629751, 370052078, 2492424772, 353393373 },
            .{ 2375079117, 202501204, 2391999998, 252968295 },
            .{ 2341779115, 169201202, 2291574680, 152542977 },
        },
        .c = .{
            .{ 589304352, 539169873, 623253122, 639965299 },
            .{ 791419620, 741285141, 690626246, 707338423 },
            .{ 454566312, 404431833, 488515082, 505227259 },
            .{ 387197292, 337062813, 286403918, 303116095 },
        },
        .d = .{
            .{ 587207168, 536876080, 620762720, 637540432 },
            .{ 788536000, 738204912, 687873696, 704651408 },
            .{ 452993408, 402662320, 486548960, 503326672 },
            .{ 385886528, 335555440, 285224224, 302001936 },
        },
    };
    try std.testing.expect(expected.eql(&round(test_start_state)));
}

test "bitcast works as vec128" {
    const gas = [4]u32{
        std.math.maxInt(u32) / 2,
        std.math.maxInt(u32) / 5,
        std.math.maxInt(u32) / 7,
        std.math.maxInt(u32) / 11,
    };
    const liquid: [2]u64 = @bitCast(gas);
    const solid: u128 = @bitCast(gas);
    const expected_liquid: [2]u64 = .{ 3689348816030400511, 1676976733025356068 };
    const expected_solid = 30934760611684291960695475747055206399;
    try std.testing.expect(mem.eql(u64, &expected_liquid, &liquid));
    try std.testing.expect(expected_solid == solid);
    try std.testing.expect(mem.eql(u32, &gas, &@as([4]u32, @bitCast(liquid))));
    try std.testing.expect(mem.eql(u32, &gas, &@as([4]u32, @bitCast(solid))));
}

test "rotate_right" {
    const start = [4]u32{ 16, 17, 18, 19 };
    inline for (.{
        .{ 0, .{ 16, 17, 18, 19 } },
        .{ 1, .{ 8, 2147483656, 9, 2147483657 } },
        .{ 16, .{ 1048576, 1114112, 1179648, 1245184 } },
        .{ 29, .{ 128, 136, 144, 152 } },
        .{ 64, .{ 16, 17, 18, 19 } },
    }) |x| {
        const n, const expected = x;
        inline for (0..4) |i| {
            const start_item = start[i];
            // const right = n % 32;
            // const left: u32 = (32 - right) % 32;
            // const out = start_item << left | start_item >> @intCast(right);
            try std.testing.expect(expected[i] == std.math.rotr(u32, start_item, n));
        }
    }
}

test "add_pos works" {
    const input = .{ 1, 2, 3, 4 };
    const i = 1892390;
    const output = wrappingAddToFirstHalf(input, i);
    try std.testing.expect(mem.eql(u32, &[4]u32{ 1892391, 2, 3, 4 }, &output));
}

test "transpose works" {
    const input = [4][4][4]u32{
        .{ .{ 0, 1, 2, 3 }, .{ 4, 5, 6, 7 }, .{ 8, 9, 10, 11 }, .{ 12, 13, 14, 15 } },
        .{ .{ 16, 17, 18, 19 }, .{ 20, 21, 22, 23 }, .{ 24, 25, 26, 27 }, .{ 28, 29, 30, 31 } },
        .{ .{ 32, 33, 34, 35 }, .{ 36, 37, 38, 39 }, .{ 40, 41, 42, 43 }, .{ 44, 45, 46, 47 } },
        .{ .{ 48, 49, 50, 51 }, .{ 52, 53, 54, 55 }, .{ 56, 57, 58, 59 }, .{ 60, 61, 62, 63 } },
    };
    const actual = transpose4(input);
    const expected: [4][4][4]u32 = .{
        .{ .{ 0, 1, 2, 3 }, .{ 16, 17, 18, 19 }, .{ 32, 33, 34, 35 }, .{ 48, 49, 50, 51 } },
        .{ .{ 4, 5, 6, 7 }, .{ 20, 21, 22, 23 }, .{ 36, 37, 38, 39 }, .{ 52, 53, 54, 55 } },
        .{ .{ 8, 9, 10, 11 }, .{ 24, 25, 26, 27 }, .{ 40, 41, 42, 43 }, .{ 56, 57, 58, 59 } },
        .{ .{ 12, 13, 14, 15 }, .{ 28, 29, 30, 31 }, .{ 44, 45, 46, 47 }, .{ 60, 61, 62, 63 } },
    };
    for (0..4) |i| for (0..4) |j| {
        try std.testing.expect(mem.eql(u32, &expected[i][j], &actual[i][j]));
    };
}
