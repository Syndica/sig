//! Enforces line length for code and comment lines.
//!
//! Multiline string literal lines are ignored:
//!
//! ```zig
//! \\ this multiline string literal line may exceed the limit
//! ```
//!
//! Lines containing URLs (any occurrence of "http") are exempt from length checks.
//! This includes `[word] URL` reference patterns (e.g. `// [agave] https://...`).
//!
//! For code lines, trailing comments do not count toward line length. Lines between
//! `// zig fmt: off` and `// zig fmt: on` are ignored, and `// sig fmt:` directives
//! work the same way. Doc comment variants (`/// sig fmt: off/on`) are also supported.
//!
//! Generated and data-heavy files can be listed in `excluded_paths`. Stale entries are reported
//! by `lintExcludedPathsExist` so exclusions stay tied to files that exist.

const std = @import("std");

const cli = @import("cli.zig");
const core = @import("core.zig");

const max_line_length = 100;

// Generated and data-heavy files with intentional long lines.
const excluded_paths = [_][]const u8{
    "lib/crypto/ed25519/wycheproof.zig",
};

/// Sanity check files skipped exist to keep list in sync with repo
pub fn lintExcludedPathsExist(ctx: *core.Context, files: *const core.SourceFiles) !void {
    for (excluded_paths) |excluded| {
        if (files.get(excluded) == null) {
            try ctx.addDiagnostic(
                excluded,
                1,
                1,
                .line_length,
                "excluded path does not exist, remove it from excluded_paths " ++
                    "if no longer part of project",
            );
        }
    }
}

pub fn lint(ctx: *core.Context, file: *const core.SourceFile) !void {
    if (isExcluded(file.path)) return;

    var fmt_off = false;
    var it = std.mem.splitScalar(u8, file.source, '\n');
    var line_no: usize = 1;
    while (it.next()) |raw_line| : (line_no += 1) {
        // Note this lint does not identify tabs since `zig fmt` handles them.
        const line = std.mem.trimRight(u8, raw_line, "\r");
        const stripped_left = std.mem.trimLeft(u8, line, " ");

        if (startsFmtDirective(stripped_left, "off")) {
            fmt_off = true;
        } else if (startsFmtDirective(stripped_left, "on")) {
            fmt_off = false;
            continue;
        }
        if (fmt_off) continue;

        // Multiline string literals are exempt.
        if (std.mem.startsWith(u8, stripped_left, "\\\\")) continue;

        // Lines containing URLs are exempt from line length limits.
        if (std.mem.indexOf(u8, line, "http") != null) continue;

        // For full-line comments, measure the entire line.
        // For code lines, measure only the code part (before any trailing comment).
        const measured_len = if (std.mem.startsWith(u8, stripped_left, "//"))
            line.len
        else
            std.mem.trimRight(u8, beforeLineComment(line), " ").len;

        if (measured_len > max_line_length) {
            try ctx.addDiagnostic(
                file.path,
                line_no,
                max_line_length + 1,
                .line_length,
                "line exceeds 100 columns",
            );
        }
    }
}

fn isExcluded(path: []const u8) bool {
    for (excluded_paths) |excluded| {
        if (std.mem.eql(u8, path, excluded)) return true;
    }
    return false;
}

fn startsFmtDirective(stripped: []const u8, state: []const u8) bool {
    const prefixes = [_][]const u8{ "// zig fmt: ", "// sig fmt: ", "/// zig fmt: ", "/// sig fmt: " };
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, stripped, prefix) and
            std.mem.eql(u8, stripped[prefix.len..], state))
        {
            return true;
        }
    }
    return false;
}

fn beforeLineComment(line: []const u8) []const u8 {
    if (std.mem.indexOf(u8, line, "//")) |index| return line[0..index];
    return line;
}

test "detects code and comments, ignores multiline strings fmt-off and trailing comments" {
    const allocator = std.heap.page_allocator;
    const config: cli.Config = .{};
    var ctx: core.Context = .{ .arena = allocator, .config = config };

    const source = "const x = 123456789012345678901234567890123456789012345678901234567890" ++
        "12345678901234567890123456789012345678901;\n" ++
        "// 123456789012345678901234567890123456789012345678901234567890" ++
        "12345678901234567890123456789012345678901\n" ++
        "\\\\ long multiline string ignored even when it is far longer than one hundred " ++
        "columns 123456789012345678901234567890\n" ++
        "// zig fmt: off\n" ++
        "const y = 123456789012345678901234567890123456789012345678901234567890" ++
        "12345678901234567890123456789012345678901;\n" ++
        "// zig fmt: on\n" ++
        "const z = 1; // 12345678901234567890123456789012345678901234567890" ++
        "123456789012345678901234567890\n";
    const source_z = try allocator.dupeZ(u8, source);
    const ast = try std.zig.Ast.parse(allocator, source_z, .zig);
    const file: core.SourceFile = .{
        .path = "lib/example.zig",
        .source = source_z,
        .ast = ast,
    };
    try lint(&ctx, &file);
    // Long code line (line 1) and long comment (line 2) are flagged.
    // Multiline string (line 3), fmt-off code (line 5), and trailing comment (line 7)
    // are not flagged.
    try std.testing.expectEqual(2, ctx.diagnostics.items.len);
}

test "doc comment /// sig fmt: off/on directives are recognized" {
    const allocator = std.heap.page_allocator;
    const config: cli.Config = .{};
    var ctx: core.Context = .{ .arena = allocator, .config = config };

    const source =
        "/// sig fmt: off\n" ++
        "///     \\phi_i'(x) = \\sum_{l: bit l set in i} S_l'(x) \\prod_{{l: bit l set in i} \\ {l}} S_{l'}(x) extra padding here\n" ++
        "/// sig fmt: on\n" ++
        "/// this long doc comment without fmt-off should be flagged 12345678901234567890123456789012345678901234567890\n";
    const source_z = try allocator.dupeZ(u8, source);
    const ast = try std.zig.Ast.parse(allocator, source_z, .zig);
    const file: core.SourceFile = .{
        .path = "lib/example.zig",
        .source = source_z,
        .ast = ast,
    };
    try lint(&ctx, &file);
    // Only line 4 (the long doc comment outside fmt-off) should be flagged.
    try std.testing.expectEqual(1, ctx.diagnostics.items.len);
}

test "lines containing URLs are exempt from line length" {
    const allocator = std.heap.page_allocator;
    const config: cli.Config = .{};
    var ctx: core.Context = .{ .arena = allocator, .config = config };

    const source =
        // Code line with a URL — should be exempt even though it exceeds 100 columns.
        "const url = \"https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L471-L474\";\n" ++
        // Inline comment with URL on a code line — also exempt.
        "const x = 1; // see https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L471-L474\n" ++
        // Full-line comment with URL — also exempt.
        "// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L471-L474\n" ++
        // Plain long code line without URL — should be flagged.
        "const y = 123456789012345678901234567890123456789012345678901234567890" ++
        "12345678901234567890123456789012345678901;\n";
    const source_z = try allocator.dupeZ(u8, source);
    const ast = try std.zig.Ast.parse(allocator, source_z, .zig);
    const file: core.SourceFile = .{
        .path = "lib/example.zig",
        .source = source_z,
        .ast = ast,
    };
    try lint(&ctx, &file);
    // Only the plain long code line should be flagged, not the URL lines.
    try std.testing.expectEqual(1, ctx.diagnostics.items.len);
}

test "excluded paths report stale entries" {
    const allocator = std.heap.page_allocator;
    const config: cli.Config = .{};
    var ctx: core.Context = .{ .arena = allocator, .config = config };
    const files: core.SourceFiles = .{ .items = .empty };

    try lintExcludedPathsExist(&ctx, &files);

    try std.testing.expectEqual(excluded_paths.len, ctx.diagnostics.items.len);
    try std.testing.expectEqualStrings(excluded_paths[0], ctx.diagnostics.items[0].path);
    try std.testing.expectEqualStrings(
        "excluded path does not exist, remove it from excluded_paths " ++
            "if no longer part of project",
        ctx.diagnostics.items[0].message,
    );
}
