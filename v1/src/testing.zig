const std = @import("std");

pub fn expectEqualDeepWithOverrides(
    expected: anytype,
    actual: anytype,
    /// Expects methods:
    /// * `fn compare(expected: anytype, actual: @TypeOf(expected)) !bool`:
    ///   Should return true if the values were compared, and otherwise false
    ///   to fall back to default handling of comparison.
    compare_ctx: anytype,
) !void {
    var sub_accesses: std.ArrayListUnmanaged(SubAccess) = .{};
    defer sub_accesses.deinit(std.testing.allocator);
    errdefer testPrint("Difference occurs at `expected`{f}", .{
        SubAccess.suffixListFmt(sub_accesses.items),
    });
    expectEqualDeepWithOverridesImpl(
        expected,
        actual,
        &sub_accesses,
        compare_ctx,
    ) catch |err| {
        if (@errorReturnTrace()) |ert| ert.index = 0;
        return err;
    };
}

const SubAccess = union(enum) {
    field: []const u8,
    index: usize,

    fn suffixListFmt(items: []const SubAccess) SuffixListFmt {
        return .{ .items = items };
    }

    const SuffixListFmt = struct {
        items: []const SubAccess,

        pub fn format(
            self: SuffixListFmt,
            writer: *std.Io.Writer,
        ) std.Io.Writer.Error!void {
            for (self.items) |access| {
                switch (access) {
                    .field => |field| {
                        try writer.writeAll(".");
                        try writer.print("{f}", .{std.zig.fmtId(field)});
                    },
                    .index => |index| try writer.print("[{d}]", .{index}),
                }
            }
        }
    };
};

fn expectEqualDeepWithOverridesImpl(
    expected: anytype,
    actual: anytype,
    sub_accesses: *std.ArrayListUnmanaged(SubAccess),
    /// Expects methods:
    /// * `fn compare(expected: anytype, actual: @TypeOf(expected)) !bool`:
    ///   Should return true if the values were compared, and otherwise false
    ///   to fall back to default handling of comparison.
    compare_ctx: anytype,
) !void {
    const T = @TypeOf(expected, actual);
    if (@TypeOf(expected) != T or @TypeOf(actual) != T) return expectEqualDeepWithOverridesImpl(
        @as(T, expected),
        @as(T, actual),
        compare_ctx,
    );

    if (try compare_ctx.compare(expected, actual)) return;
    switch (@typeInfo(T)) {
        else => try std.testing.expectEqual(expected, actual),
        .vector => |info| {
            const expected_array: [info.len]info.child = expected;
            const actual_array: [info.len]info.child = actual;
            return expectEqualDeepWithOverridesImpl(
                expected_array,
                actual_array,
                sub_accesses,
                compare_ctx,
            );
        },
        .array => |info| {
            const expected_slice: []const info.child = &expected;
            const actual_slice: []const info.child = &actual;
            return expectEqualDeepWithOverridesImpl(
                expected_slice,
                actual_slice,
                sub_accesses,
                compare_ctx,
            );
        },
        .pointer => |pointer| switch (pointer.size) {
            .c => try std.testing.expectEqual(expected, actual),
            .many => if (pointer.sentinel()) |sentinel| {
                const expected_slice = std.mem.sliceTo(expected, sentinel);
                const actual_slice = std.mem.sliceTo(actual, sentinel);
                return expectEqualDeepWithOverridesImpl(
                    expected_slice,
                    actual_slice,
                    sub_accesses,
                    compare_ctx,
                );
            } else return std.testing.expectEqual(expected, actual),
            .one => switch (@typeInfo(pointer.child)) {
                .@"fn", .@"opaque" => try std.testing.expectEqual(expected, actual),
                else => return expectEqualDeepWithOverridesImpl(
                    expected.*,
                    actual.*,
                    sub_accesses,
                    compare_ctx,
                ),
            },
            .slice => {
                if (expected.len != actual.len) {
                    testPrint("Slice len not the same, expected {d}, found {d}\n", .{
                        expected.len,
                        actual.len,
                    });
                    return error.TestExpectedEqual;
                }

                try sub_accesses.ensureUnusedCapacity(std.testing.allocator, 1);
                var i: usize = 0;
                while (i < expected.len) : (i += 1) {
                    sub_accesses.appendAssumeCapacity(.{ .index = i });
                    try expectEqualDeepWithOverridesImpl(
                        expected[i],
                        actual[i],
                        sub_accesses,
                        compare_ctx,
                    );
                    _ = sub_accesses.pop();
                }
            },
        },

        .@"struct" => |info| {
            try sub_accesses.ensureUnusedCapacity(std.testing.allocator, 1);
            inline for (info.fields) |field| {
                sub_accesses.appendAssumeCapacity(.{ .field = field.name });
                try expectEqualDeepWithOverridesImpl(
                    @field(expected, field.name),
                    @field(actual, field.name),
                    sub_accesses,
                    compare_ctx,
                );
                _ = sub_accesses.pop();
            }
        },
        .@"union" => |info| {
            const Tag = info.tag_type orelse
                @compileError("Unable to compare untagged union values");

            const expected_tag: Tag = expected;
            const actual_tag: Tag = actual;
            try expectEqualDeepWithOverridesImpl(
                expected_tag,
                actual_tag,
                sub_accesses,
                compare_ctx,
            );

            switch (expected) {
                inline else => |expected_val, tag| {
                    const actual_val = @field(actual, @tagName(tag));
                    try sub_accesses.append(std.testing.allocator, .{ .field = @tagName(tag) });
                    try expectEqualDeepWithOverridesImpl(
                        expected_val,
                        actual_val,
                        sub_accesses,
                        compare_ctx,
                    );
                    _ = sub_accesses.pop();
                },
            }
        },
        .optional => if (expected) |expected_payload| {
            if (actual) |actual_payload| {
                try expectEqualDeepWithOverridesImpl(
                    expected_payload,
                    actual_payload,
                    sub_accesses,
                    compare_ctx,
                );
            } else {
                testPrint("expected {any}, found null\n", .{expected_payload});
                return error.TestExpectedEqual;
            }
        } else {
            if (actual) |actual_payload| {
                testPrint("expected null, found {any}\n", .{actual_payload});
                return error.TestExpectedEqual;
            }
        },
        .error_union => if (expected) |expected_payload| {
            if (actual) |actual_payload| {
                try expectEqualDeepWithOverridesImpl(
                    expected_payload,
                    actual_payload,
                    sub_accesses,
                    compare_ctx,
                );
            } else |actual_err| {
                testPrint("expected {any}, found {any}\n", .{ expected_payload, actual_err });
                return error.TestExpectedEqual;
            }
        } else |expected_err| {
            if (actual) |actual_payload| {
                testPrint("expected {any}, found {any}\n", .{ expected_err, actual_payload });
                return error.TestExpectedEqual;
            } else |actual_err| {
                try expectEqualDeepWithOverridesImpl(
                    expected_err,
                    actual_err,
                    sub_accesses,
                    compare_ctx,
                );
            }
        },
    }
}

fn testPrint(comptime fmt: []const u8, args: anytype) void {
    if (@inComptime()) {
        @compileError(std.fmt.comptimePrint(fmt, args));
    } else if (std.testing.backend_can_print) {
        std.debug.print(fmt ++ "\n", args);
    }
}
