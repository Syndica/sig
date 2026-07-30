const std = @import("std");
const sig = @import("../sig.zig");
const table = @import("reed_solomon_table.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.array_list.Managed;

pub const ReedSolomon = struct {
    allocator: Allocator,
    data_shard_count: usize,
    parity_shard_count: usize,
    total_shard_count: usize,
    matrix: Matrix,
    rc: *sig.sync.ReferenceCounter,
    // TODO lru cache of matrices

    pub fn init(allocator: Allocator, data_shards: usize, parity_shards: usize) !ReedSolomon {
        if (data_shards == 0) {
            return error.TooFewDataShards;
        }
        if (parity_shards == 0) {
            return error.TooFewParityShards;
        }
        if (data_shards + parity_shards > field.order) {
            return error.TooManyShards;
        }
        const total_shards = data_shards + parity_shards;

        const vandermonde = try Matrix.initVandermonde(allocator, total_shards, data_shards);
        defer vandermonde.deinit(allocator);
        const top = try vandermonde.subMatrix(allocator, 0, 0, data_shards, data_shards);
        defer top.deinit(allocator);
        const inverted = try top.invert(allocator);
        defer inverted.deinit(allocator);
        const matrix = try vandermonde.multiply(allocator, inverted);

        const rc = try allocator.create(sig.sync.ReferenceCounter);
        rc.* = .{};

        return ReedSolomon{
            .allocator = allocator,
            .data_shard_count = data_shards,
            .total_shard_count = total_shards,
            .parity_shard_count = parity_shards,
            .matrix = matrix,
            .rc = rc,
        };
    }

    pub fn acquire(self: *ReedSolomon) bool {
        return self.rc.acquire();
    }

    pub fn deinit(self: *ReedSolomon) void {
        if (self.rc.release()) {
            self.allocator.destroy(self.rc);
            self.matrix.deinit(self.allocator);
        }
    }

    pub fn reconstruct(
        self: *const ReedSolomon,
        allocator: Allocator,
        shards: []?[]const u8,
        data_only: bool,
    ) !void {
        if (shards.len > self.total_shard_count) return error.TooManyShards;
        if (shards.len < self.total_shard_count) return error.TooFewShards;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        var number_present: usize = 0;
        var maybe_shard_len: ?usize = null;

        const data_shard_count = self.data_shard_count;

        for (shards) |maybe_shard| if (maybe_shard) |shard| {
            if (shard.len == 0) {
                return error.EmptyShard;
            }
            number_present += 1;
            if (maybe_shard_len) |old_len| {
                if (shard.len != old_len) {
                    return error.IncorrectShardSize;
                }
            } else {
                maybe_shard_len = shard.len;
            }
        };

        if (number_present == self.total_shard_count) {
            // Cool.  All of the shards are there.  We don't
            // need to do anything.
            return;
        }

        // More complete sanity check
        if (number_present < data_shard_count) {
            return error.TooFewShardsPresent;
        }

        const shard_len = maybe_shard_len.?; // must be non-null since at least one shard is present

        // Pull out an array holding just the shards that
        // correspond to the rows of the submatrix.  These shards
        // will be the input to the decoding process that re-creates
        // the missing data shards.
        //
        // Also, create an array of indices of the valid rows we do have
        // and the invalid rows we don't have.
        //
        // The valid indices are used to construct the data decode matrix,
        // the invalid indices are used to key the data decode matrix
        // in the data decode matrix cache.
        //
        // We only need exactly N valid indices, where N = `data_shard_count`,
        // as the data decode matrix is a N x N matrix, thus only needs
        // N valid indices for determining the N rows to pick from
        // `self.matrix`.
        var sub_shards = try ArrayList([]const u8).initCapacity(arena_allocator, data_shard_count);
        var missing_data_slices = try ArrayList([]u8).initCapacity(arena_allocator, self.parity_shard_count);
        var missing_parity_slices = try ArrayList([]u8).initCapacity(arena_allocator, self.parity_shard_count);
        var valid_indices = try ArrayList(usize).initCapacity(arena_allocator, data_shard_count);
        var invalid_indices = try ArrayList(usize).initCapacity(arena_allocator, data_shard_count);

        // Separate the shards into groups
        for (shards, 0..) |maybe_shard, matrix_row| {
            if (maybe_shard) |shard| {
                // present shard
                if (sub_shards.items.len < data_shard_count) {
                    sub_shards.appendAssumeCapacity(shard);
                    valid_indices.appendAssumeCapacity(matrix_row);
                } else {
                    // Already have enough shards in `sub_shards`
                    // as we only need N shards, where N = `data_shard_count`,
                    // for the data decode matrix
                    //
                    // So nothing to do here
                }
            } else if (matrix_row >= data_shard_count and data_only) {
                // this is a parity shard and we're not going to recover it
                try invalid_indices.append(matrix_row); // TODO should be able to assume capacity but this failed
            } else {
                // missing shard that we need to recover
                const new_shard = try allocator.alloc(u8, shard_len);
                shards[matrix_row] = new_shard;
                @memset(new_shard, 0);
                if (matrix_row < data_shard_count) {
                    missing_data_slices.appendAssumeCapacity(new_shard);
                } else {
                    missing_parity_slices.appendAssumeCapacity(new_shard);
                }
                try invalid_indices.append(matrix_row); // TODO should be able to assume capacity but this failed
            }
        }

        const data_decode_matrix = try self
            .getDataDecodeMatrix(arena_allocator, valid_indices.items);

        // Re-create any data shards that were missing.
        //
        // The input to the coding is all of the shards we actually
        // have, and the output is the missing data shards. The computation
        // is done using the special decode matrix we just built.
        var matrix_rows = try ArrayList([]const u8)
            .initCapacity(arena_allocator, self.parity_shard_count);

        for (invalid_indices.items) |i_slice| {
            if (i_slice >= data_shard_count) break;
            matrix_rows.appendAssumeCapacity(data_decode_matrix.getRow(i_slice));
        }

        self.codeSlices(matrix_rows.items, sub_shards.items, missing_data_slices.items);

        if (data_only) {
            return;
        }

        // Now that we have all of the data shards intact, we can
        // compute any of the parity that is missing.
        //
        // The input to the coding is ALL of the data shards, including
        // any that we just calculated.  The output is whichever of the
        // parity shards were missing.
        matrix_rows = try ArrayList([]const u8)
            .initCapacity(arena_allocator, self.parity_shard_count);
        const parity_rows = try self.getParityRows(arena_allocator);

        var found = false;
        for (invalid_indices.items) |i_slice| {
            if (!found and i_slice < data_shard_count) continue;
            found = true;
            matrix_rows.appendAssumeCapacity(parity_rows.items[i_slice - data_shard_count]);
        }

        {
            // Gather up all the data shards.
            // old data shards are in `sub_shards`,
            // new ones are in `missing_data_slices`.
            var i_new_data_slice: usize = 0;

            var all_data_slices = try ArrayList([]const u8)
                .initCapacity(arena_allocator, data_shard_count);

            var pusher = struct {
                i_old_data_slice: usize = 0,
                next_maybe_good: usize = 0,
                data_slices: *ArrayList([]const u8),
                sub_shards: *ArrayList([]const u8),

                fn pushGoodUpTo(
                    this: *@This(),
                    up_to: usize,
                ) void {
                    // if next_maybe_good == up_to, this loop is a no-op.
                    for (this.next_maybe_good..up_to) |_| {
                        // push all good indices we just skipped.
                        this.data_slices.appendAssumeCapacity(
                            this.sub_shards.items[this.i_old_data_slice],
                        );
                        this.i_old_data_slice += 1;
                    }
                    this.next_maybe_good = up_to + 1;
                }
            }{ .data_slices = &all_data_slices, .sub_shards = &sub_shards };

            for (invalid_indices.items) |i_slice| {
                if (i_slice >= data_shard_count) break;
                pusher.pushGoodUpTo(i_slice);
                all_data_slices.appendAssumeCapacity(missing_data_slices.items[i_new_data_slice]);
                i_new_data_slice += 1;
            }
            pusher.pushGoodUpTo(data_shard_count);

            // Now do the actual computation for the missing
            // parity shards
            self.codeSlices(matrix_rows.items, all_data_slices.items, missing_parity_slices.items);
        }
    }

    fn getDataDecodeMatrix(
        self: ReedSolomon,
        allocator: Allocator,
        valid_indices: []const usize,
    ) !Matrix {
        // TODO perf: get from lru cache

        // Pull out the rows of the matrix that correspond to the shards that
        // we have and build a square matrix. This matrix could be used to
        // generate the shards that we have from the original data.
        var sub_matrix = try Matrix
            .initZeros(allocator, self.data_shard_count, self.data_shard_count); // TODO is zero needed?
        for (valid_indices, 0..) |valid_index, sub_matrix_row| {
            for (0..self.data_shard_count) |c| {
                sub_matrix.set(sub_matrix_row, c, self.matrix.get(valid_index, c));
            }
        }
        // Invert the matrix, so we can go from the encoded shards back to the
        // original data. Then pull out the row that generates the shard that
        // we want to decode. Note that since this matrix maps back to the
        // original data, it can be used to create a data shard, but not a
        // parity shard.
        const data_decode_matrix = try sub_matrix.invert(allocator);
        // Cache the inverted matrix for future use keyed on the indices of the
        // invalid rows.

        // TODO perf: put in lru cache
        return data_decode_matrix;
    }

    fn getParityRows(self: ReedSolomon, allocator: Allocator) Allocator.Error!ArrayList([]const u8) {
        const matrix = &self.matrix;
        var parity_rows = try ArrayList([]const u8).initCapacity(allocator, self.parity_shard_count);
        for (self.data_shard_count..self.total_shard_count) |i| {
            parity_rows.appendAssumeCapacity(matrix.getRow(i));
        }
        return parity_rows;
    }

    fn codeSlices(
        self: ReedSolomon,
        matrix_rows: []const []const u8,
        inputs: []const []const u8,
        outputs: []const []u8,
    ) void {
        for (0..self.data_shard_count) |i_input| {
            codeSingleSlice(matrix_rows, i_input, inputs[i_input], outputs);
        }
    }
};

fn codeSingleSlice(
    matrix_rows: []const []const u8,
    i_input: usize,
    input: []const u8,
    outputs: []const []u8,
) void {
    for (outputs, 0..) |out, i_row| {
        const matrix_row_to_use = matrix_rows[i_row][i_input];
        if (i_input == 0) {
            field.mulSlice(matrix_row_to_use, input, out);
        } else {
            field.mulSliceAdd(matrix_row_to_use, input, out);
        }
    }
}

pub const Matrix = struct {
    row_count: usize,
    col_count: usize,
    data: []u8,

    const Self = Matrix;

    pub fn deinit(self: Self, allocator: Allocator) void {
        allocator.free(self.data);
    }

    pub fn initZeros(allocator: Allocator, rows: usize, cols: usize) Allocator.Error!Self {
        const self = try initUndefined(allocator, rows, cols);
        @memset(self.data, 0);
        return self;
    }

    pub fn initIdentity(allocator: Allocator, size: usize) Allocator.Error!Self {
        const self = try initZeros(allocator, size, size);
        for (0..size) |i| {
            self.set(i, i, 1);
        }
        return self;
    }

    pub fn initVandermonde(allocator: Allocator, rows: usize, cols: usize) Allocator.Error!Self {
        var self = try initUndefined(allocator, rows, cols);
        for (0..rows) |r| {
            // doesn't matter what `r_a` is as long as it's unique.
            // then the vandermonde matrix is invertible.
            const r_a: u8 = @intCast(r);
            for (0..cols) |c| {
                self.data[self.index(r, c)] = field.exp(r_a, c);
            }
        }

        return self;
    }

    fn initUndefined(allocator: Allocator, rows: usize, cols: usize) Allocator.Error!Self {
        return .{
            .row_count = rows,
            .col_count = cols,
            .data = try allocator.alloc(u8, rows * cols),
        };
    }

    pub fn subMatrix(
        self: Self,
        allocator: Allocator,
        rmin: usize,
        cmin: usize,
        rmax: usize,
        cmax: usize,
    ) Allocator.Error!Self {
        const result = try initUndefined(allocator, rmax - rmin, cmax - cmin);
        for (rmin..rmax) |r| {
            for (cmin..cmax) |c| {
                // TODO memcpy may be faster
                result.data[result.index(r - rmin, c - cmin)] = self.get(r, c);
            }
        }
        return result;
    }

    pub fn multiply(self: Self, allocator: Allocator, rhs: Self) Allocator.Error!Self {
        if (self.col_count != rhs.row_count) {
            @panic("Column count on left is different from row count on right");
        }
        var result = try initUndefined(allocator, self.row_count, rhs.col_count);
        for (0..self.row_count) |r| {
            for (0..rhs.col_count) |c| {
                var val: u8 = 0;
                for (0..self.col_count) |i| {
                    const mul = field.mul(self.get(r, i), rhs.get(i, c));
                    val = field.add(val, mul);
                }
                result.data[result.index(r, c)] = val;
            }
        }
        return result;
    }

    pub fn invert(self: Self, allocator: Allocator) !Self {
        if (!self.isSquare()) {
            @panic("Trying to invert a non-square matrix");
        }

        const row_count = self.row_count;
        const col_count = self.col_count;

        const identity = try initIdentity(allocator, row_count);
        defer identity.deinit(allocator);
        var work = try self.augment(allocator, identity);
        defer work.deinit(allocator);
        try work.gaussianElimination();

        return try work.subMatrix(allocator, 0, row_count, col_count, col_count * 2);
    }

    pub fn isSquare(self: Self) bool {
        return self.row_count == self.col_count;
    }

    pub fn augment(self: Self, allocator: Allocator, rhs: Self) Allocator.Error!Self {
        if (self.row_count != rhs.row_count) {
            @panic("Matrices do not have the same row count, lhs: {}, rhs: {}");
        }
        var result = try initUndefined(allocator, self.row_count, self.col_count + rhs.col_count);
        for (0..self.row_count) |r| {
            for (0..self.col_count) |c| {
                result.data[result.index(r, c)] = self.get(r, c);
            }
            for (0..rhs.col_count) |c| {
                result.data[result.index(r, self.col_count + c)] = rhs.get(r, c);
            }
        }

        return result;
    }

    pub fn gaussianElimination(self: *Self) error{SingularMatrix}!void {
        for (0..self.row_count) |r| {
            if (self.get(r, r) == 0) {
                for (r + 1..self.row_count) |r_below| {
                    if (self.get(r_below, r) != 0) {
                        self.swapRows(r, r_below);
                        break;
                    }
                }
            }
            // If we couldn't find one, the matrix is singular.
            if (self.get(r, r) == 0) {
                return error.SingularMatrix;
            }
            // Scale to 1.
            if (self.get(r, r) != 1) {
                const scale = field.div(1, self.get(r, r));
                for (0..self.col_count) |c| {
                    self.data[self.index(r, c)] = field.mul(scale, self.get(r, c));
                }
            }
            // Make everything below the 1 be a 0 by subtracting
            // a multiple of it.  (Subtraction and addition are
            // both exclusive (the Galois field) |or|.)
            for (r + 1..self.row_count) |r_below| {
                if (self.get(r_below, r) != 0) {
                    const scale = self.get(r_below, r);
                    for (0..self.col_count) |c| {
                        self.data[self.index(r_below, c)] = field.add(
                            self.get(r_below, c),
                            field.mul(scale, self.get(r, c)),
                        );
                    }
                }
            }
        }

        // Now clear the part above the main diagonal.
        for (0..self.row_count) |d| {
            for (0..d) |r_above| {
                if (self.get(r_above, d) != 0) {
                    const scale = self.get(r_above, d);
                    for (0..self.col_count) |c| {
                        self.data[self.index(r_above, c)] = field.add(
                            self.get(r_above, c),
                            field.mul(scale, self.get(d, c)),
                        );
                    }
                }
            }
        }
    }

    pub inline fn get(self: Self, row: usize, col: usize) u8 {
        return self.data[self.index(row, col)];
    }

    pub inline fn set(self: Self, row: usize, col: usize, val: u8) void {
        self.data[self.index(row, col)] = val;
    }

    inline fn index(self: Self, row: usize, col: usize) usize {
        return row * self.col_count + col;
    }

    pub fn getRow(self: *const Self, row: usize) []const u8 {
        const start, const end = self.rowStartEnd(row);
        return self.data[start..end];
    }

    pub fn swapRows(self: *Self, r1: usize, r2: usize) void {
        const r1_s = r1 * self.col_count;
        const r2_s = r2 * self.col_count;

        if (r1 == r2) {
            return;
        } else {
            for (0..self.col_count) |i| {
                const tmp1 = self.data[r1_s + i];
                self.data[r1_s + i] = self.data[r2_s + i];
                self.data[r2_s + i] = tmp1;
            }
        }
    }

    fn rowStartEnd(self: Self, row: usize) struct { usize, usize } {
        const start = row * self.col_count;
        return .{ start, start + self.col_count };
    }
};

const field = struct {
    const order = 256;
    const max = 255;

    fn add(a: u8, b: u8) u8 {
        return a ^ b;
    }

    fn mul(a: u8, b: u8) u8 {
        if (a == 0 or b == 0) return 0;
        return table.mul[@intCast(a)][@intCast(b)];
    }
    pub fn div(a: u8, b: u8) u8 {
        if (a == 0) return 0;
        if (b == 0) @panic("divide by zero");
        const log_a = table.log[@intCast(a)];
        const log_b = table.log[@intCast(b)];
        var log_result = @as(isize, @intCast(log_a)) - @as(isize, @intCast(log_b));
        if (log_result < 0) {
            log_result += max;
        }
        return table.exp[@intCast(log_result)];
    }

    fn exp(a: u8, n: usize) u8 {
        return if (n == 0)
            1
        else if (a == 0)
            0
        else blk: {
            const log_a = table.log[@intCast(a)];
            var log_result = @as(usize, @intCast(log_a)) * n;
            while (max <= log_result) {
                log_result -= max; // TODO mod?
            }
            break :blk table.exp[log_result];
        };
    }

    // TODO perf: see reed_solomon_erasure::galois_8 for an approach with better performance
    fn mulSlice(elem: u8, input: []const u8, out: []u8) void {
        // std.debug.assert(input.len == out.len);
        for (input, out) |i, *o| {
            o.* = mul(elem, i);
        }
    }

    // TODO perf: see reed_solomon_erasure::galois_8 for an approach with better performance
    fn mulSliceAdd(elem: u8, input: []const u8, out: []u8) void {
        // std.debug.assert(input.len == out.len);
        for (input, out) |i, *o| {
            o.* = add(o.*, mul(elem, i));
        }
    }
};

test "ReedSolomon.reconstruct basic 0-11 sequence with any missing combination" {
    const allocator = std.testing.allocator;
    var rs = try ReedSolomon.init(allocator, 3, 2);
    defer rs.deinit();
    var master_copy = [5][4]u8{
        .{ 0, 1, 2, 3 },
        .{ 4, 5, 6, 7 },
        .{ 8, 9, 10, 11 },
        .{ 12, 13, 14, 15 },
        .{ 16, 17, 18, 19 },
    };
    for (0..5) |i| for (0..5) |j| {
        var data = ArrayList(?[]const u8).init(allocator);
        defer data.deinit();
        defer for (data.items) |md| if (md) |d| allocator.free(d);
        for (0..5) |s| {
            if (s == i or s == j) {
                try data.append(null);
            } else {
                const to_include = try allocator.alloc(u8, master_copy[s].len);
                @memcpy(to_include, master_copy[s][0..]);
                try data.append(to_include);
            }
        }
        try rs.reconstruct(allocator, data.items, false);
        for (0..5) |s| {
            try std.testing.expectEqualSlices(u8, &master_copy[s], data.items[s].?);
        }
    };
}

test "ReedSolomon.reconstruct lorem ipsum with any missing combination" {
    // somewhat redundant with other tests and this is the slowest one
    if (!sig.build_options.long_tests) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var rs = try ReedSolomon.init(allocator, 7, 4);
    defer rs.deinit();
    const num_shards = 11;
    const master_copy = [num_shards][]const u8{
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod",
        "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ve",
        "niam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea c",
        "ommodo consequat. Duis aute irure dolor in reprehenderit in voluptate v",
        "elit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaec",
        "at cupidatat non proident, sunt in culpa qui officia deserunt mollit an",
        "im id est laborum.                                                     ",
        &.{
            84,  123, 122, 105, 123, 40,  103, 107, 107, 127, 57,  51,  61,  96,  100, 113, 48,  126,
            95,  46,  99,  108, 114, 99,  39,  127, 109, 97,  38,  47,  104, 36,  39,  45,  125, 47,
            41,  121, 51,  32,  115, 53,  109, 109, 126, 61,  56,  105, 122, 105, 31,  113, 31,  59,
            124, 58,  47,  56,  40,  123, 101, 111, 112, 35,  117, 40,  119, 56,  40,  61,  57,
        },
        &.{
            149, 45,  221, 144, 32,  40, 199, 26,  68,  194, 233, 120, 144, 174, 219, 255, 236, 166,
            182, 157, 133, 209, 123, 22, 0,   29,  191, 96,  162, 224, 191, 228, 239, 228, 137, 129,
            254, 117, 225, 90,  74,  15, 26,  219, 46,  50,  52,  104, 119, 196, 93,  80,  97,  166,
            134, 65,  29,  196, 75,  85, 67,  194, 4,   11,  36,  47,  33,  94,  73,  230, 182,
        },
        &.{
            130, 124, 84,  98,  124, 141, 137, 165, 147, 206, 77,  115, 20,  177, 34,  215, 253, 33,
            9,   139, 163, 243, 122, 84,  94,  48,  20,  63,  189, 199, 91,  217, 131, 179, 62,  65,
            145, 36,  234, 108, 20,  49,  104, 178, 197, 24,  58,  251, 108, 210, 243, 17,  32,  87,
            61,  89,  28,  241, 243, 150, 80,  224, 35,  15,  0,   175, 87,  132, 252, 189, 44,
        },
        &.{
            88,  26,  179, 228, 193, 169, 135, 130, 213, 89, 169, 255, 160, 211, 34,  11, 63,  155,
            39,  182, 103, 141, 250, 18,  140, 224, 172, 48, 201, 76,  37,  219, 207, 35, 4,   27,
            213, 240, 157, 93,  176, 1,   205, 109, 6,   34, 106, 119, 149, 103, 136, 99, 19,  9,
            97,  79,  215, 149, 196, 33,  248, 89,  107, 91, 56,  135, 220, 65,  33,  41, 210,
        },
    };
    for (0..num_shards) |i| for (0..num_shards) |j| for (0..num_shards) |k| for (0..num_shards) |l| {
        var data = ArrayList(?[]const u8).init(allocator);
        defer data.deinit();
        defer for (data.items) |md| if (md) |d| allocator.free(d);
        for (0..num_shards) |s| {
            if (s == i or s == j or s == k or s == l) {
                try data.append(null);
            } else {
                const to_include = try allocator.alloc(u8, master_copy[s].len);
                @memcpy(to_include, master_copy[s]);
                try data.append(to_include);
            }
        }
        try rs.reconstruct(allocator, data.items, false);
        for (0..num_shards) |s| {
            try std.testing.expectEqualSlices(u8, master_copy[s], data.items[s].?);
        }
    };
}

test "ReedSolomon.reconstruct shards constructed from mainnet shreds" {
    const input = @import("test_shreds.zig").mainnet_recovery_shards;
    const expected = @import("test_shreds.zig").mainnet_expected_recovered_shards;
    var actual = std.array_list.Managed(?[]const u8).init(std.testing.allocator);
    defer actual.deinit();
    for (input) |i| try actual.append(i);
    var rs = try ReedSolomon.init(std.testing.allocator, 7, 21);
    defer rs.deinit();
    try rs.reconstruct(std.testing.allocator, actual.items, false);
    defer for (input, actual.items) |i, a| if (i == null) std.testing.allocator.free(a.?);
    for (expected, actual.items) |e, a| {
        try std.testing.expectEqualSlices(u8, e, a.?);
    }
}
