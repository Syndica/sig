const std = @import("std");

const cli = @import("cli.zig");
const Allocator = std.mem.Allocator;

pub const max_source_file_size = 1024 * 1024;
pub const parse_errors_diagnostic_id = "parse_errors";

pub const Diagnostic = struct {
    path: []const u8,
    line: usize,
    column: usize,
    rule_id: []const u8,
    message: []const u8,
};

pub const Edit = struct {
    start: usize,
    end: usize,
    replacement: []const u8,
};

pub const SourceFile = struct {
    path: []const u8,
    source: [:0]u8,
    ast: std.zig.Ast,
    has_changes: bool = false,

    /// Path is borrowed and must live at least as long as the returned SourceFile.
    pub fn readAndParse(arena: Allocator, path: []const u8) !SourceFile {
        const source = try std.fs.cwd().readFileAllocOptions(
            arena,
            path,
            max_source_file_size,
            null,
            .of(u8),
            0,
        );
        const ast = try std.zig.Ast.parse(arena, source, .zig);
        return .{ .path = path, .source = source, .ast = ast };
    }

    pub fn hasParseErrors(self: *const SourceFile) bool {
        return self.ast.errors.len != 0;
    }

    /// Borrows `source`, replacing the existing source and refreshing the AST for this
    /// SourceFile.
    pub fn replaceSource(
        self: *SourceFile,
        arena: Allocator,
        source: [:0]u8,
        fix_name: []const u8,
    ) !void {
        const ast = try std.zig.Ast.parse(arena, source, .zig);
        if (ast.errors.len != 0) {
            std.debug.print(
                "lint internal error: fix {s} produced source with parse errors for {s}\n",
                .{ fix_name, self.path },
            );
            return error.PostFixParseFailed;
        }

        self.source = source;
        self.ast = ast;
        self.has_changes = true;
    }

    pub fn writeIfChanged(self: *const SourceFile) !void {
        if (!self.has_changes) {
            return;
        }
        try std.fs.cwd().writeFile(.{ .sub_path = self.path, .data = self.source });
    }
};

pub const SourceFiles = struct {
    items: std.ArrayList(SourceFile),

    pub fn collectAndReadRecursive(
        arena: Allocator,
        root_paths: []const []const u8,
    ) !SourceFiles {
        var collected: std.ArrayList([]const u8) = .empty;
        for (root_paths) |path| try collectPathRecursive(arena, path, &collected);
        sortStrings(collected.items);

        var files: SourceFiles = .{ .items = .empty };

        for (collected.items) |path| {
            const file = try SourceFile.readAndParse(arena, path);
            try files.items.append(arena, file);
        }

        return files;
    }

    pub fn get(self: *const SourceFiles, path: []const u8) ?*SourceFile {
        const comparer = struct {
            fn compare(target_path: []const u8, file: SourceFile) std.math.Order {
                return std.mem.order(u8, target_path, file.path);
            }
        };

        const index = std.sort.binarySearch(SourceFile, self.items.items, path, comparer.compare);
        if (index) |i| {
            if (std.mem.eql(u8, self.items.items[i].path, path)) {
                return &self.items.items[i];
            }
        }

        return null;
    }
};

pub const Context = struct {
    config: cli.Config,
    diagnostics: std.ArrayList(Diagnostic) = .empty,
    /// This is the "global arena" for all linting operations and diagnostics. It is never reset or
    /// freed and will retain all allocations for the full linting execution.
    arena: Allocator,

    /// Arguments are borrowed and must live at least as long as this Context.
    pub fn addDiagnostic(
        self: *Context,
        path: []const u8,
        line: usize,
        column: usize,
        rule: cli.Rule,
        message: []const u8,
    ) !void {
        try self.addDiagnosticId(path, line, column, rule.id(), message);
    }

    /// Arguments are borrowed and must live at least as long as this Context.
    pub fn addDiagnosticId(
        self: *Context,
        path: []const u8,
        line: usize,
        column: usize,
        rule_id: []const u8,
        message: []const u8,
    ) !void {
        try self.diagnostics.append(self.arena, .{
            .path = path,
            .line = line,
            .column = column,
            .rule_id = rule_id,
            .message = message,
        });
    }
};

pub fn printDiagnostics(diagnostics: []const Diagnostic) !void {
    for (diagnostics) |diag| {
        std.debug.print("{s}:{d}:{d}: error[{s}]: {s}\n", .{
            diag.path,
            diag.line,
            diag.column,
            diag.rule_id,
            diag.message,
        });
    }
}

/// `paths` are borrowed from `path` or allocated by `arena`.
fn collectPathRecursive(
    arena: Allocator,
    path: []const u8,
    paths: *std.ArrayList([]const u8),
) anyerror!void {
    const stat = try std.fs.cwd().statFile(path);
    switch (stat.kind) {
        .file => {
            if (std.mem.endsWith(u8, path, ".zig")) {
                try paths.append(arena, path);
            }
        },
        .directory => if (!isSkippedDir(std.fs.path.basename(path))) {
            var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
            defer dir.close();
            var it = dir.iterate();
            while (try it.next()) |entry| {
                if (entry.kind == .directory and isSkippedDir(entry.name)) continue;
                const child = try std.fs.path.join(arena, &.{ path, entry.name });
                try collectPathRecursive(arena, child, paths);
            }
        },
        else => {},
    }
}

fn isSkippedDir(name: []const u8) bool {
    const skipped_dirs = [_][]const u8{
        ".git",
        ".zig-cache",
        "zig-cache",
        "zig-out",
        "__pycache__",
    };
    for (skipped_dirs) |skipped| {
        if (std.mem.eql(u8, name, skipped)) return true;
    }
    return false;
}

pub fn sortStrings(strings: [][]const u8) void {
    std.mem.sort([]const u8, strings, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
}

pub fn sortEdits(edits: []Edit) void {
    std.mem.sort(Edit, edits, {}, struct {
        fn lessThan(_: void, a: Edit, b: Edit) bool {
            return a.start < b.start;
        }
    }.lessThan);
}

pub fn applySortedEdits(
    arena: Allocator,
    source: []const u8,
    edits: []const Edit,
) ![:0]u8 {
    var out: std.ArrayList(u8) = .empty;
    var cursor: usize = 0;
    for (edits) |edit| {
        if (edit.start < cursor) return error.OverlappingEdits;
        if (edit.start > edit.end or edit.end > source.len) return error.InvalidEditRange;
        try out.appendSlice(arena, source[cursor..edit.start]);
        try out.appendSlice(arena, edit.replacement);
        cursor = edit.end;
    }
    try out.appendSlice(arena, source[cursor..]);
    return out.toOwnedSliceSentinel(arena, 0);
}

pub fn runZigFmt(allocator: Allocator, path: []const u8) !void {
    var child = std.process.Child.init(&.{ "zig", "fmt", path }, allocator);
    const term = try child.spawnAndWait();
    if (term != .Exited or term.Exited != 0) return error.ZigFmtFailed;
}

pub const Location = struct {
    line: usize,
    column: usize,
};

/// Returns one-indexed line and column for byte offset in source.
/// Offsets past end of source clamp to end of source.
pub fn lineColumn(source: []const u8, offset: usize) Location {
    var line: usize = 1;
    var column: usize = 1;
    var i: usize = 0;
    while (i < @min(offset, source.len)) : (i += 1) {
        if (source[i] == '\n') {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    return .{ .line = line, .column = column };
}

/// Returns byte offset of start of line containing offset.
/// Offsets past end of source clamp to end of source.
pub fn lineStart(source: []const u8, offset: usize) usize {
    const end = @min(offset, source.len);
    return if (std.mem.lastIndexOfScalar(u8, source[0..end], '\n')) |index|
        index + 1
    else
        0;
}

/// Returns byte offset just after line ending for line containing offset.
/// If line has no trailing newline, returns source length.
pub fn lineEndIncludingNewline(source: []const u8, offset: usize) usize {
    const start = @min(offset, source.len);
    return if (std.mem.indexOfScalarPos(u8, source, start, '\n')) |index|
        index + 1
    else
        source.len;
}

test "collectAndReadRecursive fails when root path is missing" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.FileNotFound,
        SourceFiles.collectAndReadRecursive(allocator, &.{"lib/.missing_lint_path.zig"}),
    );
}

test "line helpers clamp offsets and include newline" {
    const source = "abc\ndef\nxyz";

    try std.testing.expectEqual(Location{ .line = 1, .column = 1 }, lineColumn(source, 0));
    try std.testing.expectEqual(Location{ .line = 1, .column = 4 }, lineColumn(source, 3));
    try std.testing.expectEqual(Location{ .line = 2, .column = 1 }, lineColumn(source, 4));
    try std.testing.expectEqual(Location{ .line = 2, .column = 3 }, lineColumn(source, 6));
    try std.testing.expectEqual(
        Location{ .line = 3, .column = 4 },
        lineColumn(source, source.len + 10),
    );

    try std.testing.expectEqual(0, lineStart(source, 0));
    try std.testing.expectEqual(0, lineStart(source, 3));
    try std.testing.expectEqual(4, lineStart(source, 4));
    try std.testing.expectEqual(4, lineStart(source, 6));
    try std.testing.expectEqual(8, lineStart(source, source.len + 10));

    try std.testing.expectEqual(4, lineEndIncludingNewline(source, 0));
    try std.testing.expectEqual(4, lineEndIncludingNewline(source, 3));
    try std.testing.expectEqual(8, lineEndIncludingNewline(source, 4));
    try std.testing.expectEqual(source.len, lineEndIncludingNewline(source, 8));
    try std.testing.expectEqual(source.len, lineEndIncludingNewline(source, source.len + 10));
}
