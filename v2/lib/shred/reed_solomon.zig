const std = @import("std");
const tracy = @import("tracy");
const lib = @import("../lib.zig");
const rs_table = @import("reed_solomon_table.zig");

const Signature = lib.solana.Signature;
const Shred = lib.shred.Shred;
const Packet = lib.net.Packet;
const FecSetCtx = @import("receiver.zig").FecSetCtx;

// Reconstructs data shreds when 32/64 shreds have been received
pub fn reconstructFecSet(fec_set_ctx: *FecSetCtx) void {
    const zone = tracy.Zone.init(@src(), .{ .name = "reconstructFecSet" });
    defer zone.deinit();

    const data_count = FecSetCtx.fec_shred_cnt;
    const code_count = FecSetCtx.fec_shred_cnt;
    const total_count = data_count + code_count;

    // Build present[] mask and collect erasure shard length from first present shred
    var present: [total_count]bool = @splat(false);
    var shard_len: usize = 0;

    for (0..data_count) |i| {
        if (fec_set_ctx.data_shreds_received.isSet(i)) {
            present[i] = true;
            if (shard_len == 0) {
                const shred = Shred.fromBufferUnchecked(&fec_set_ctx.data_shreds_buf[i]);
                if (shred.erasureFragment()) |frag| {
                    shard_len = frag.len;
                }
            }
        }
    }
    for (0..code_count) |i| {
        if (fec_set_ctx.code_shreds_received.isSet(i)) {
            present[data_count + i] = true;
            if (shard_len == 0) {
                const shred = Shred.fromBufferUnchecked(&fec_set_ctx.code_shreds_buf[i]);
                if (shred.erasureFragment()) |frag| {
                    shard_len = frag.len;
                }
            }
        }
    }

    if (shard_len == 0) return; // no valid shreds found

    // Collect 32 valid indices (indices of present shreds in encoding_matrix row order)
    var valid_indices: [data_count]u8 = undefined;
    var valid_count: u8 = 0;
    for (0..total_count) |i| {
        if (present[i]) {
            valid_indices[valid_count] = @intCast(i);
            valid_count += 1;
            if (valid_count == data_count) break;
        }
    }

    if (valid_count < data_count) return; // not enough shreds

    // Build 32x32 sub-matrix by picking rows from encoding_matrix
    var sub_matrix: [data_count][data_count]u8 = undefined;
    for (0..data_count) |r| {
        sub_matrix[r] = encoding_matrix[valid_indices[r]];
    }

    // Invert sub_matrix via Gaussian elimination on augmented [sub_matrix | identity]
    var aug: [data_count][data_count * 2]u8 = undefined;
    for (0..data_count) |r| {
        for (0..data_count) |c| {
            aug[r][c] = sub_matrix[r][c];
            aug[r][data_count + c] = @intFromBool(r == c);
        }
    }

    // Forward elimination
    for (0..data_count) |r| {
        if (aug[r][r] == 0) {
            for (r + 1..data_count) |r_below| {
                if (aug[r_below][r] != 0) {
                    std.mem.swap([data_count * 2]u8, &aug[r], &aug[r_below]);
                    break;
                }
            }
        }
        if (aug[r][r] == 0) {
            std.log.warn("FEC reconstruction: singular matrix at row {}", .{r});
            return;
        }
        if (aug[r][r] != 1) {
            const scale = field.div(1, aug[r][r]);
            for (0..data_count * 2) |c| {
                aug[r][c] = field.mul(scale, aug[r][c]);
            }
        }
        for (r + 1..data_count) |r_below| {
            if (aug[r_below][r] != 0) {
                const scale = aug[r_below][r];
                for (0..data_count * 2) |c| {
                    aug[r_below][c] = field.add(aug[r_below][c], field.mul(scale, aug[r][c]));
                }
            }
        }
    }
    // Back-substitution
    for (0..data_count) |d| {
        for (0..d) |r_above| {
            if (aug[r_above][d] != 0) {
                const scale = aug[r_above][d];
                for (0..data_count * 2) |c| {
                    aug[r_above][c] = field.add(aug[r_above][c], field.mul(scale, aug[d][c]));
                }
            }
        }
    }

    // Extract inverted matrix from right half
    var inv: [data_count][data_count]u8 = undefined;
    for (0..data_count) |r| {
        for (0..data_count) |c| {
            inv[r][c] = aug[r][data_count + c];
        }
    }

    // Find leader signature from any present data or code shred (first 64 bytes)
    var leader_sig: [Signature.SIZE]u8 = undefined;
    var have_sig = false;
    for (0..data_count) |i| {
        if (fec_set_ctx.data_shreds_received.isSet(i)) {
            @memcpy(&leader_sig, fec_set_ctx.data_shreds_buf[i][0..Signature.SIZE]);
            have_sig = true;
            break;
        }
    }
    if (!have_sig) {
        for (0..code_count) |i| {
            if (fec_set_ctx.code_shreds_received.isSet(i)) {
                @memcpy(&leader_sig, fec_set_ctx.code_shreds_buf[i][0..Signature.SIZE]);
                have_sig = true;
                break;
            }
        }
    }

    // Collect pointers to erasure shards for the 32 valid indices
    var shard_ptrs: [data_count][]const u8 = undefined;
    for (0..data_count) |k| {
        const idx = valid_indices[k];
        if (idx < data_count) {
            const shred = Shred.fromBufferUnchecked(&fec_set_ctx.data_shreds_buf[idx]);
            shard_ptrs[k] = (shred.erasureFragment() orelse return);
        } else {
            const shred = Shred.fromBufferUnchecked(&fec_set_ctx.code_shreds_buf[idx - data_count]);
            shard_ptrs[k] = (shred.erasureFragment() orelse return);
        }
    }

    // For each missing data shred, reconstruct its erasure shard
    for (0..data_count) |i| {
        if (present[i]) continue; // already have this data shred

        // We need the i-th row of the inverted matrix to recover data shard i
        const inv_row = &inv[i];

        // Destination: write directly into the packet buffer
        const dest_packet = &fec_set_ctx.data_shreds_buf[i];

        // First, copy leader signature into bytes 0..64
        if (have_sig) {
            @memcpy(dest_packet[0..Signature.SIZE], &leader_sig);
        }

        // For data shreds, erasure shard starts at offset 64 (after signature)
        // and ends at headers_size + capacity. We compute it the same way.
        // The erasure shard for data shreds covers bytes [64 .. 64 + shard_len]
        const dest_start = Signature.SIZE; // 64
        const dest_end = dest_start + shard_len;
        if (dest_end > Packet.capacity) return;

        const dest = dest_packet[dest_start..dest_end];

        // Multiply: dest[byte] = sum over k of (inv_row[k] * shard_ptrs[k][byte])
        // First pass: dest = inv_row[0] * shard_ptrs[0]
        const coeff0 = inv_row[0];
        for (0..shard_len) |b| {
            dest[b] = field.mul(coeff0, shard_ptrs[0][b]);
        }
        // Remaining passes: dest += inv_row[k] * shard_ptrs[k]
        for (1..data_count) |k| {
            const coeff = inv_row[k];
            if (coeff == 0) continue;
            for (0..shard_len) |b| {
                dest[b] = field.add(dest[b], field.mul(coeff, shard_ptrs[k][b]));
            }
        }

        // Mark this data shred as received
        fec_set_ctx.data_shreds_received.set(i);
    }
}

// GF(2^8) arithmetic and Reed-Solomon encoding matrix for erasure coding.
// All operations use pre-computed lookup tables from reed_solomon_table.zig.
const field = struct {
    inline fn add(a: u8, b: u8) u8 {
        return a ^ b;
    }

    inline fn mul(a: u8, b: u8) u8 {
        return rs_table.mul[a][b];
    }

    inline fn div(a: u8, b: u8) u8 {
        if (a == 0) return 0;
        const log_a = rs_table.log[a];
        const log_b = rs_table.log[b];
        const log_result: i16 = @as(i16, log_a) - @as(i16, log_b);
        return rs_table.exp[@intCast(if (log_result < 0) log_result + 255 else log_result)];
    }

    fn exp(a: u8, n: usize) u8 {
        if (n == 0) return 1;
        if (a == 0) return 0;
        var log_result: usize = @as(usize, rs_table.log[a]) * n;
        while (log_result >= 255) {
            log_result -= 255;
        }
        return rs_table.exp[log_result];
    }
};

/// Comptime-generated 64x32 encoding matrix for Reed-Solomon with data_count=32, code_count=32.
/// Top 32 rows = identity matrix (for data shreds), bottom 32 rows = parity coefficients.
/// Derived from: Vandermonde(64x32) * inverse(Vandermonde_top(32x32))
const encoding_matrix: [64][32]u8 = blk: {
    @setEvalBranchQuota(1_000_000);

    const total = 64;
    const data = 32;

    // Step 1: Build 64x32 Vandermonde matrix
    var vandermonde: [total][data]u8 = undefined;
    for (0..total) |r| {
        for (0..data) |c| {
            vandermonde[r][c] = field.exp(@intCast(r), c);
        }
    }

    // Step 2: Extract top 32x32 submatrix and invert via Gaussian elimination
    // Build augmented matrix [top | identity]
    var aug: [data][data * 2]u8 = undefined;
    for (0..data) |r| {
        for (0..data) |c| {
            aug[r][c] = vandermonde[r][c];
        }
        for (0..data) |c| {
            aug[r][data + c] = if (r == c) 1 else 0;
        }
    }

    // Gaussian elimination (forward)
    for (0..data) |r| {
        // Find pivot
        if (aug[r][r] == 0) {
            for (r + 1..data) |r_below| {
                if (aug[r_below][r] != 0) {
                    std.mem.swap([data * 2]u8, &aug[r], &aug[r_below]);
                    break;
                }
            }
        }
        // Scale pivot row
        if (aug[r][r] != 1) {
            const scale = field.div(1, aug[r][r]);
            for (0..data * 2) |c| {
                aug[r][c] = field.mul(scale, aug[r][c]);
            }
        }
        // Eliminate below
        for (r + 1..data) |r_below| {
            if (aug[r_below][r] != 0) {
                const scale = aug[r_below][r];
                for (0..data * 2) |c| {
                    aug[r_below][c] = field.add(aug[r_below][c], field.mul(scale, aug[r][c]));
                }
            }
        }
    }
    // Back-substitution (eliminate above)
    for (0..data) |d| {
        for (0..d) |r_above| {
            if (aug[r_above][d] != 0) {
                const scale = aug[r_above][d];
                for (0..data * 2) |c| {
                    aug[r_above][c] = field.add(aug[r_above][c], field.mul(scale, aug[d][c]));
                }
            }
        }
    }

    // Extract inverted top matrix from right half of augmented matrix
    var inv_top: [data][data]u8 = undefined;
    for (0..data) |r| {
        for (0..data) |c| {
            inv_top[r][c] = aug[r][data + c];
        }
    }

    // Step 3: Multiply Vandermonde(64x32) * inv_top(32x32) = encoding_matrix(64x32)
    var result: [total][data]u8 = undefined;
    for (0..total) |r| {
        for (0..data) |c| {
            var val: u8 = 0;
            for (0..data) |i| {
                val = field.add(val, field.mul(vandermonde[r][i], inv_top[i][c]));
            }
            result[r][c] = val;
        }
    }

    break :blk result;
};
