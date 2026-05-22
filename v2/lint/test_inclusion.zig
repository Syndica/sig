//! Ensures each source directory has companion Zig file that imports tests for sibling source files.
//!
//! For files:
//!
//! ```text
//! lib/foo.zig
//! lib/bar.zig
//! lib/crypto.zig
//! lib/crypto/ed25519.zig
//! ```
//!
//! `lib/lib.zig` is root companion file and must contain managed test imports for `foo.zig`,
//! `bar.zig`, and `crypto.zig`. `lib/crypto.zig` is companion file for `lib/crypto/` and
//! must contain managed test imports for `ed25519.zig`. Missing companion files are reported.
//!
//! Managed block format:
//!
//! ```zig
//! comptime {
//!     if (@import("builtin").is_test) {
//!         _ = @import("foo.zig");
//!     }
//! }
//! ```

const std = @import("std");

const core = @import("core.zig");

const Allocator = std.mem.Allocator;

const ManagedBlock = struct {
    start: usize,
    end: usize,
    malformed: bool,
    custom_logic: bool,
    imports: std.ArrayList([]const u8) = .empty,
};

const managed_test_inclusion_wrapper = "if (@import(\"builtin\").is_test) {";
const obsolete_ref_all_decls = "std.testing.refAllDecls(@This())";

pub fn lint(
    ctx: *core.Context,
    root_file: []const u8,
    source_files: *const core.SourceFiles,
) !void {
    const root_dir = std.fs.path.dirname(root_file) orelse
        return error.InvalidTestInclusionRootFile;

    var source_paths: std.ArrayList([]const u8) = .empty;
    for (source_files.items.items) |source_file| {
        // gather source files that are in or under the root directory
        if (source_file.path.len > root_dir.len and
            std.mem.startsWith(u8, source_file.path, root_dir) and
            source_file.path[root_dir.len] == '/')
        {
            try source_paths.append(ctx.arena, source_file.path);
        }
    }

    // sort by file's directory then by path, required for correct grouping of files by directory
    // for example full path sort can split lib/ into two groups:
    // lib/crypto.zig, lib/crypto/ed25519.zig, lib/lib.zig
    // dir sort keeps lib/ files together:
    // lib/crypto.zig, lib/lib.zig, lib/crypto/ed25519.zig
    std.mem.sort([]const u8, source_paths.items, root_dir, lessByDirThenPath);

    var i: usize = 0;
    while (i < source_paths.items.len) {
        const dir_path = sourceDir(root_dir, source_paths.items[i]);
        const start = i;
        while (i < source_paths.items.len and
            std.mem.eql(u8, sourceDir(root_dir, source_paths.items[i]), dir_path))
        {
            i += 1;
        }
        try lintDir(ctx, root_file, root_dir, dir_path, source_paths.items[start..i], source_files);
    }
}

fn lintDir(
    ctx: *core.Context,
    root_file: []const u8,
    root_dir: []const u8,
    dir_path: []const u8,
    dir_source_paths: []const []const u8,
    source_files: *const core.SourceFiles,
) !void {
    const is_root_dir = std.mem.eql(u8, dir_path, root_dir);
    const companion_path = if (is_root_dir)
        root_file
    else
        try std.fmt.allocPrint(ctx.arena, "{s}.zig", .{dir_path});

    const companion_file = source_files.get(companion_path) orelse {
        try ctx.addDiagnostic(
            companion_path,
            1,
            1,
            .test_inclusion,
            "missing companion file",
        );
        return;
    };

    var all_expected_imports: std.ArrayList([]const u8) = .empty;
    for (dir_source_paths) |source_path| {
        if (std.mem.eql(u8, source_path, companion_path)) continue;
        try all_expected_imports.append(
            ctx.arena,
            try expectedImportPath(root_dir, companion_path, source_path),
        );
    }
    core.sortStrings(all_expected_imports.items);

    const source = companion_file.source;
    const skipped_imports = try skippedTestInclusionImports(ctx.arena, source);
    const expected_imports = try filteredExpectedImports(
        ctx.arena,
        all_expected_imports.items,
        skipped_imports.items,
    );

    const managed_blocks = try findManagedBlocks(ctx.arena, source);

    switch (ctx.config.mode) {
        .check => try check(
            ctx,
            companion_path,
            all_expected_imports.items.len != 0,
            expected_imports.items,
            source,
            managed_blocks.items,
        ),
        .fix => {
            if (managed_blocks.items.len > 1) {
                try addExtraManagedBlockDiagnostics(
                    ctx,
                    companion_path,
                    source,
                    managed_blocks.items[1..],
                );
                return;
            }
            try fix(
                ctx,
                companion_file,
                all_expected_imports.items,
                skipped_imports.items,
                if (managed_blocks.items.len == 0) null else managed_blocks.items[0],
            );
        },
    }
}

fn sourceDir(root_dir: []const u8, file: []const u8) []const u8 {
    return std.fs.path.dirname(file) orelse root_dir;
}

fn lessByDirThenPath(root_dir: []const u8, left: []const u8, right: []const u8) bool {
    const left_dir = sourceDir(root_dir, left);
    const right_dir = sourceDir(root_dir, right);
    return switch (std.mem.order(u8, left_dir, right_dir)) {
        .lt => true,
        .gt => false,
        .eq => std.mem.lessThan(u8, left, right),
    };
}

fn expectedImportPath(
    root_dir: []const u8,
    companion_path: []const u8,
    file: []const u8,
) ![]const u8 {
    const companion_dir = std.fs.path.dirname(companion_path) orelse root_dir;
    if (std.mem.startsWith(u8, file, companion_dir) and
        file.len > companion_dir.len and file[companion_dir.len] == '/')
    {
        return file[companion_dir.len + 1 ..];
    }
    return error.InvalidTestInclusionImportPath;
}

fn check(
    ctx: *core.Context,
    companion_path: []const u8,
    expects_managed_block: bool,
    expected_imports: []const []const u8,
    source: []const u8,
    managed_blocks: []const ManagedBlock,
) !void {
    try checkObsoleteRefAllDecls(ctx, companion_path, source);

    const managed: ?ManagedBlock = if (managed_blocks.len == 0) null else managed_blocks[0];
    for (managed_blocks) |block| {
        const loc = core.lineColumn(source, block.start);
        if (block.malformed) {
            try addTestInclusionDiagnostic(
                ctx,
                companion_path,
                loc,
                "malformed managed test inclusion block",
            );
        }
        if (block.custom_logic) {
            try addTestInclusionDiagnostic(
                ctx,
                companion_path,
                loc,
                "managed test inclusion block contains custom logic",
            );
        }
    }

    if (!expects_managed_block) {
        try addExtraManagedBlockDiagnostics(ctx, companion_path, source, managed_blocks);
        return;
    }
    if (managed_blocks.len > 1) {
        try addExtraManagedBlockDiagnostics(
            ctx,
            companion_path,
            source,
            managed_blocks[1..],
        );
        return;
    }

    const block = managed orelse {
        try addTestInclusionDiagnostic(
            ctx,
            companion_path,
            .{ .line = 1, .column = 1 },
            "missing managed test inclusion block",
        );
        return;
    };

    const loc = core.lineColumn(source, block.start);
    if (!isSorted(block.imports.items)) {
        try addTestInclusionDiagnostic(
            ctx,
            companion_path,
            loc,
            "unsorted test inclusion imports",
        );
    }
    try addStringDifferenceDiagnostics(
        ctx,
        companion_path,
        loc,
        expected_imports,
        block.imports.items,
        "missing test inclusion import",
    );
    try addStringDifferenceDiagnostics(
        ctx,
        companion_path,
        loc,
        block.imports.items,
        expected_imports,
        "extra test inclusion import",
    );
}

fn addTestInclusionDiagnostic(
    ctx: *core.Context,
    companion_path: []const u8,
    loc: core.Location,
    message: []const u8,
) !void {
    try ctx.addDiagnostic(
        companion_path,
        loc.line,
        loc.column,
        .test_inclusion,
        message,
    );
}

fn addExtraManagedBlockDiagnostics(
    ctx: *core.Context,
    companion_path: []const u8,
    source: []const u8,
    managed_blocks: []const ManagedBlock,
) !void {
    for (managed_blocks) |block| {
        try addTestInclusionDiagnostic(
            ctx,
            companion_path,
            core.lineColumn(source, block.start),
            "extra managed test inclusion block",
        );
    }
}

fn addStringDifferenceDiagnostics(
    ctx: *core.Context,
    companion_path: []const u8,
    loc: core.Location,
    candidates: []const []const u8,
    existing: []const []const u8,
    message: []const u8,
) !void {
    for (candidates) |candidate| {
        if (!containsString(existing, candidate)) {
            try addTestInclusionDiagnostic(ctx, companion_path, loc, message);
        }
    }
}

fn checkObsoleteRefAllDecls(
    ctx: *core.Context,
    companion_path: []const u8,
    source: []const u8,
) !void {
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, source, index, obsolete_ref_all_decls)) |pos| {
        try addTestInclusionDiagnostic(
            ctx,
            companion_path,
            core.lineColumn(source, pos),
            "obsolete refAllDecls(@This()) test inclusion block",
        );
        index = pos + obsolete_ref_all_decls.len;
    }
}

fn fix(
    ctx: *core.Context,
    companion_file: *core.SourceFile,
    all_expected_imports: []const []const u8,
    skipped_imports: []const []const u8,
    target: ?ManagedBlock,
) !void {
    var edits: std.ArrayList(core.Edit) = .empty;

    const source = companion_file.source;
    const companion_path = companion_file.path;
    const canonical = if (all_expected_imports.len == 0)
        null
    else
        try canonicalTestBlock(
            ctx.arena,
            all_expected_imports,
            skipped_imports,
            if (target == null) .insert else .replace,
        );

    try checkObsoleteRefAllDecls(ctx, companion_path, source);

    if (target) |block| {
        if (block.custom_logic) {
            const loc = core.lineColumn(source, block.start);
            try addTestInclusionDiagnostic(
                ctx,
                companion_path,
                loc,
                "managed test inclusion block contains custom logic",
            );
            return;
        }
        const replacement = canonical orelse "";
        if (!std.mem.eql(u8, source[block.start..block.end], replacement)) {
            try edits.append(ctx.arena, .{
                .start = block.start,
                .end = block.end,
                .replacement = replacement,
            });
        }
    } else if (all_expected_imports.len != 0) {
        const insert_at = testBlockInsertOffset(source);
        try edits.append(ctx.arena, .{
            .start = insert_at,
            .end = insert_at,
            .replacement = canonical.?,
        });
    }

    if (edits.items.len == 0) return;
    core.sortEdits(edits.items);
    const fixed = try core.applySortedEdits(ctx.arena, source, edits.items);
    try companion_file.replaceSource(ctx.arena, fixed, "test_inclusion");
}

fn skippedTestInclusionImports(
    arena: Allocator,
    source: []const u8,
) !std.ArrayList([]const u8) {
    var skipped: std.ArrayList([]const u8) = .empty;

    const prefix = "// lint: skip ";
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, prefix)) continue;
        const import_path = std.mem.trim(u8, trimmed[prefix.len..], " \t\r");
        if (import_path.len == 0) continue;
        try skipped.append(arena, import_path);
    }

    return skipped;
}

fn filteredExpectedImports(
    arena: Allocator,
    expected: []const []const u8,
    skipped: []const []const u8,
) !std.ArrayList([]const u8) {
    var filtered: std.ArrayList([]const u8) = .empty;

    for (expected) |import_path| {
        if (containsString(skipped, import_path)) continue;
        try filtered.append(arena, import_path);
    }

    return filtered;
}

fn findManagedBlocks(arena: Allocator, source: []const u8) !std.ArrayList(ManagedBlock) {
    var managed_blocks: std.ArrayList(ManagedBlock) = .empty;

    var index: usize = 0;
    while (std.mem.indexOfPos(u8, source, index, "comptime")) |pos| {
        const after = pos + "comptime".len;
        if (after < source.len and isIdentChar(source[after])) {
            index = after;
            continue;
        }
        const cursor = skipWhitespace(source, after);
        if (cursor >= source.len or source[cursor] != '{') {
            index = after;
            continue;
        }
        const close = findMatchingBrace(source, cursor) orelse {
            if (try parseManagedBlock(
                arena,
                source[pos..],
                core.lineStart(source, pos),
                source.len,
            )) |parsed_block| {
                try managed_blocks.append(arena, parsed_block);
                break;
            }
            index = cursor + 1;
            continue;
        };
        if (try parseManagedBlock(
            arena,
            source[pos .. close + 1],
            core.lineStart(source, pos),
            core.lineEndIncludingNewline(source, close + 1),
        )) |parsed_block| {
            try managed_blocks.append(arena, parsed_block);
        }
        index = close + 1;
    }
    return managed_blocks;
}

fn parseManagedBlock(
    arena: Allocator,
    text: []const u8,
    start: usize,
    end: usize,
) !?ManagedBlock {
    if (std.mem.indexOf(u8, text, managed_test_inclusion_wrapper) == null) {
        return null;
    }

    const State = enum {
        comptime_open,
        test_if_open,
        body,
        outer_close,
        done,
    };

    var block: ManagedBlock = .{
        .start = start,
        .end = end,
        .malformed = false,
        .custom_logic = false,
    };

    var state: State = .comptime_open;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) {
            continue;
        }

        switch (state) {
            .comptime_open => {
                if (!std.mem.eql(u8, trimmed, "comptime {")) {
                    block.malformed = true;
                    break;
                }
                state = .test_if_open;
            },
            .test_if_open => {
                if (!std.mem.eql(u8, trimmed, managed_test_inclusion_wrapper)) {
                    block.malformed = true;
                    break;
                }
                state = .body;
            },
            .body => {
                if (std.mem.eql(u8, trimmed, "}")) {
                    state = .outer_close;
                } else if (std.mem.startsWith(u8, trimmed, "// lint: skip ")) {
                    continue;
                } else if (managedImportPath(trimmed)) |import_path| {
                    try block.imports.append(arena, import_path);
                } else if (std.mem.indexOfAny(u8, trimmed, "{}") != null) {
                    block.malformed = true;
                    break;
                } else {
                    block.custom_logic = true;
                }
            },
            .outer_close => {
                if (!std.mem.eql(u8, trimmed, "}")) {
                    block.malformed = true;
                    break;
                }
                state = .done;
            },
            .done => {
                block.malformed = true;
                break;
            },
        }
    }

    if (state != .done) {
        block.malformed = true;
    }
    if (block.malformed) {
        block.custom_logic = false;
    }
    return block;
}

fn managedImportPath(line: []const u8) ?[]const u8 {
    const prefix = "_ = @import(\"";
    const suffix = "\");";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    if (!std.mem.endsWith(u8, line, suffix)) return null;
    const import_path = line[prefix.len .. line.len - suffix.len];
    if (import_path.len == 0 or std.mem.indexOfScalar(u8, import_path, '"') != null) {
        return null;
    }
    return import_path;
}

const CanonicalTestBlockFix = enum {
    replace,
    insert,
};

fn canonicalTestBlock(
    arena: Allocator,
    imports: []const []const u8,
    skipped_imports: []const []const u8,
    context: CanonicalTestBlockFix,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "comptime {\n");
    try out.appendSlice(arena, "    if (@import(\"builtin\").is_test) {\n");
    for (imports) |import| {
        if (containsString(skipped_imports, import)) {
            try out.writer(arena).print(
                "        // lint: skip {s}\n",
                .{import},
            );
        } else {
            try out.writer(arena).print("        _ = @import(\"{s}\");\n", .{import});
        }
    }
    try out.appendSlice(arena, "    }\n");
    try out.appendSlice(arena, "}\n");
    if (context == .insert) {
        try out.appendSlice(arena, "\n");
    }
    return out.toOwnedSlice(arena);
}

fn skipWhitespace(source: []const u8, offset: usize) usize {
    var i = offset;
    while (i < source.len and std.ascii.isWhitespace(source[i])) i += 1;
    return i;
}

fn isIdentChar(char: u8) bool {
    return std.ascii.isAlphanumeric(char) or char == '_';
}

fn findMatchingBrace(source: []const u8, open: usize) ?usize {
    var depth: usize = 0;
    var i = open;
    while (i < source.len) : (i += 1) {
        switch (source[i]) {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if (depth == 0) return i;
            },
            else => {},
        }
    }
    return null;
}

fn containsString(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn isSorted(strings: []const []const u8) bool {
    if (strings.len < 2) return true;
    for (strings[1..], 1..) |item, i| {
        if (std.mem.lessThan(u8, item, strings[i - 1])) return false;
    }
    return true;
}

fn testBlockInsertOffset(source: []const u8) usize {
    var offset: usize = 0;
    while (offset < source.len) {
        const next = core.lineEndIncludingNewline(source, offset);
        const line = source[offset..@min(next, source.len)];
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0 or std.mem.startsWith(u8, trimmed, "//")) {
            offset = next;
            continue;
        }
        if ((std.mem.startsWith(u8, trimmed, "const ") or
            std.mem.startsWith(u8, trimmed, "pub const ")) and
            std.mem.indexOf(u8, trimmed, "@import(") != null)
        {
            offset = next;
            continue;
        }
        break;
    }
    while (offset < source.len and (source[offset] == '\n' or source[offset] == '\r')) offset += 1;
    return offset;
}

fn expectDiagnosticMessages(
    diagnostics: []const core.Diagnostic,
    expected_messages: []const []const u8,
) !void {
    try std.testing.expectEqual(expected_messages.len, diagnostics.len);
    for (expected_messages, 0..) |expected, i| {
        try std.testing.expectEqualStrings(expected, diagnostics[i].message);
    }
}

fn expectCheckDiagnostics(
    allocator: Allocator,
    source: []const u8,
    expects_managed_block: bool,
    expected_imports: []const []const u8,
    expected_messages: []const []const u8,
) !void {
    const managed_blocks = try findManagedBlocks(allocator, source);

    var ctx: core.Context = .{ .arena = allocator, .config = .{} };

    try check(
        &ctx,
        "lib/lib.zig",
        expects_managed_block,
        expected_imports,
        source,
        managed_blocks.items,
    );
    try expectDiagnosticMessages(ctx.diagnostics.items, expected_messages);
}

fn expectManagedBlockParse(
    allocator: Allocator,
    source: []const u8,
    expected_imports: []const []const u8,
    malformed: bool,
    custom_logic: bool,
) !void {
    const block = (try parseManagedBlock(allocator, source, 0, source.len)) orelse {
        return error.TestUnexpectedResult;
    };

    try std.testing.expectEqual(malformed, block.malformed);
    try std.testing.expectEqual(custom_logic, block.custom_logic);
    try std.testing.expectEqual(expected_imports.len, block.imports.items.len);
    for (expected_imports, block.imports.items) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
}

test "canonical block and parsing" {
    const allocator = std.heap.page_allocator;
    const imports = [_][]const u8{ "a.zig", "b.zig" };
    const block = try canonicalTestBlock(allocator, &imports, &.{}, .replace);
    try std.testing.expect(std.mem.indexOf(u8, block, "@import(\"builtin\").is_test") != null);
    try std.testing.expect(std.mem.indexOf(u8, block, "_ = @import(\"a.zig\");") != null);
    try std.testing.expect(std.mem.indexOf(u8, block, "_ = @import(\"b.zig\");") != null);
    try std.testing.expect(std.mem.endsWith(u8, block, "}\n"));

    const inserted_block = try canonicalTestBlock(allocator, &imports, &.{}, .insert);
    try std.testing.expect(std.mem.endsWith(u8, inserted_block, "}\n\n"));

    const managed_blocks = try findManagedBlocks(allocator, block);
    try std.testing.expectEqual(1, managed_blocks.items.len);
    try std.testing.expect(!managed_blocks.items[0].malformed);
    try std.testing.expect(!managed_blocks.items[0].custom_logic);
    try std.testing.expectEqual(2, managed_blocks.items[0].imports.items.len);
    try std.testing.expectEqualStrings("a.zig", managed_blocks.items[0].imports.items[0]);
    try std.testing.expectEqualStrings("b.zig", managed_blocks.items[0].imports.items[1]);
}

test "find managed blocks ignores invalid candidates" {
    const allocator = std.heap.page_allocator;
    const source =
        \\const comptime_value = 1;
        \\comptime if (true) {}
        \\comptime {
        \\    if (true) {
        \\
    ;

    const managed_blocks = try findManagedBlocks(allocator, source);
    try std.testing.expectEqual(0, managed_blocks.items.len);
}

test "find managed blocks ignores unmanaged blocks" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    const value = 1;
        \\}
        \\
    ;

    const managed_blocks = try findManagedBlocks(allocator, source);
    try std.testing.expectEqual(0, managed_blocks.items.len);
}

test "find managed blocks ignores obsolete unmanaged blocks" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    _ = std.testing.refAllDecls(@This());
        \\}
        \\
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        // lint: skip a.zig
        \\    }
        \\}
        \\
    ;

    const managed_blocks = try findManagedBlocks(allocator, source);
    try std.testing.expectEqual(1, managed_blocks.items.len);
    try std.testing.expect(!managed_blocks.items[0].malformed);
    try std.testing.expect(!managed_blocks.items[0].custom_logic);
    try std.testing.expectEqual(0, managed_blocks.items[0].imports.items.len);
}

test "managed block parser accepts skip comments" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        // lint: skip optional.zig
        \\        _ = @import("a.zig");
        \\    }
        \\}
        \\
    ;
    const expected = [_][]const u8{"a.zig"};

    try expectManagedBlockParse(allocator, source, &expected, false, false);
}

test "find managed blocks marks malformed wrapper order" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    const value = 1;
        \\    if (@import("builtin").is_test) {
        \\    }
        \\}
        \\
    ;

    const managed_blocks = try findManagedBlocks(allocator, source);
    try std.testing.expectEqual(1, managed_blocks.items.len);
    try std.testing.expect(managed_blocks.items[0].malformed);
    try std.testing.expect(!managed_blocks.items[0].custom_logic);
}

test "find managed blocks marks missing inner closing brace" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\
    ;
    const expected = [_][]const u8{"a.zig"};

    const managed_blocks = try findManagedBlocks(allocator, source);
    try std.testing.expectEqual(1, managed_blocks.items.len);
    try std.testing.expect(managed_blocks.items[0].malformed);
    try std.testing.expect(!managed_blocks.items[0].custom_logic);
    try std.testing.expectEqual(expected.len, managed_blocks.items[0].imports.items.len);
    try std.testing.expectEqualStrings(expected[0], managed_blocks.items[0].imports.items[0]);
}

test "find managed blocks marks missing outer closing brace" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\    }
        \\
    ;
    const expected = [_][]const u8{"a.zig"};

    const managed_blocks = try findManagedBlocks(allocator, source);
    try std.testing.expectEqual(1, managed_blocks.items.len);
    try std.testing.expect(managed_blocks.items[0].malformed);
    try std.testing.expect(!managed_blocks.items[0].custom_logic);
    try std.testing.expectEqual(expected.len, managed_blocks.items[0].imports.items.len);
    try std.testing.expectEqualStrings(expected[0], managed_blocks.items[0].imports.items[0]);
}

test "find managed blocks marks import before if wrapper as malformed" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    _ = @import("a.zig");
        \\    if (@import("builtin").is_test) {
        \\    }
        \\}
        \\
    ;

    const managed_blocks = try findManagedBlocks(allocator, source);
    try std.testing.expectEqual(1, managed_blocks.items.len);
    try std.testing.expect(managed_blocks.items[0].malformed);
    try std.testing.expect(!managed_blocks.items[0].custom_logic);
}

test "managed block parser marks extra content after outer brace as malformed" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\    }
        \\}
        \\const value = 1;
        \\
    ;
    const expected = [_][]const u8{"a.zig"};

    try expectManagedBlockParse(allocator, source, &expected, true, false);
}

test "check reports custom logic in managed block" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\        if (enabled) _ = value;
        \\    }
        \\}
        \\
    ;
    const expected = [_][]const u8{"a.zig"};

    try expectCheckDiagnostics(
        allocator,
        source,
        true,
        &expected,
        &.{"managed test inclusion block contains custom logic"},
    );
}

test "per-import skip keeps check scoped to remaining imports" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\        // lint: skip b.zig
        \\    }
        \\}
        \\
    ;

    const skipped = try skippedTestInclusionImports(allocator, source);
    try std.testing.expectEqual(1, skipped.items.len);
    try std.testing.expectEqualStrings("b.zig", skipped.items[0]);

    const expected_raw = [_][]const u8{ "a.zig", "b.zig" };
    const expected = try filteredExpectedImports(allocator, &expected_raw, skipped.items);
    try std.testing.expectEqual(1, expected.items.len);
    try std.testing.expectEqualStrings("a.zig", expected.items[0]);

    try expectCheckDiagnostics(allocator, source, true, expected.items, &.{});
}

test "check reports missing managed block" {
    const allocator = std.heap.page_allocator;
    const expected = [_][]const u8{"a.zig"};
    try expectCheckDiagnostics(
        allocator,
        "const value = 1;\n",
        true,
        &expected,
        &.{"missing managed test inclusion block"},
    );
}

test "check reports extra managed block" {
    const allocator = std.heap.page_allocator;
    const imports = [_][]const u8{"a.zig"};
    const source = try canonicalTestBlock(allocator, &imports, &.{}, .replace);

    try expectCheckDiagnostics(
        allocator,
        source,
        false,
        &.{},
        &.{"extra managed test inclusion block"},
    );
}

test "check reports extra managed block when multiple are present" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\    }
        \\}
        \\
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\    }
        \\}
        \\
    ;
    const expected = [_][]const u8{"a.zig"};

    try expectCheckDiagnostics(
        allocator,
        source,
        true,
        &expected,
        &.{"extra managed test inclusion block"},
    );
}

test "check reports obsolete block" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    _ = std.testing.refAllDecls(@This());
        \\}
        \\
    ;

    try expectCheckDiagnostics(
        allocator,
        source,
        false,
        &.{},
        &.{"obsolete refAllDecls(@This()) test inclusion block"},
    );
}

test "check reports malformed managed block" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    _ = @import("a.zig");
        \\    if (@import("builtin").is_test) {
        \\    }
        \\}
        \\
    ;

    try expectCheckDiagnostics(
        allocator,
        source,
        true,
        &.{},
        &.{"malformed managed test inclusion block"},
    );
}

test "check reports unsorted imports" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("b.zig");
        \\        _ = @import("a.zig");
        \\    }
        \\}
        \\
    ;
    const expected = [_][]const u8{ "a.zig", "b.zig" };

    try expectCheckDiagnostics(
        allocator,
        source,
        true,
        &expected,
        &.{"unsorted test inclusion imports"},
    );
}

test "check reports missing and extra imports" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\        _ = @import("c.zig");
        \\    }
        \\}
        \\
    ;
    const expected = [_][]const u8{ "a.zig", "b.zig" };

    try expectCheckDiagnostics(
        allocator,
        source,
        true,
        &expected,
        &.{
            "missing test inclusion import",
            "extra test inclusion import",
        },
    );
}

test "fix skips files with multiple managed blocks" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\    }
        \\}
        \\
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\    }
        \\}
        \\
    ;
    const path = try allocator.dupe(u8, "lib/lib.zig");
    const source_z = try allocator.dupeZ(u8, source);
    const ast = try std.zig.Ast.parse(allocator, source_z, .zig);

    var files: core.SourceFiles = .{ .items = .empty };
    try files.items.append(allocator, .{
        .path = path,
        .source = source_z,
        .ast = ast,
    });

    var ctx: core.Context = .{
        .arena = allocator,
        .config = .{ .mode = .fix },
    };

    try lintDir(&ctx, "lib/lib.zig", "lib", "lib", &.{ "lib/lib.zig", "lib/a.zig" }, &files);

    try std.testing.expectEqual(1, ctx.diagnostics.items.len);
    try std.testing.expectEqualStrings(
        "extra managed test inclusion block",
        ctx.diagnostics.items[0].message,
    );
    try std.testing.expect(!files.items.items[0].has_changes);
    try std.testing.expectEqualStrings(source, files.items.items[0].source);
}

test "fix preserves blank lines around managed block" {
    const allocator = std.heap.page_allocator;
    const source =
        \\const std = @import("std");
        \\
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\        _ = @import("b.zig");
        \\    }
        \\}
        \\
        \\pub const value = 1;
        \\
    ;
    const expected =
        \\const std = @import("std");
        \\
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        _ = @import("a.zig");
        \\    }
        \\}
        \\
        \\pub const value = 1;
        \\
    ;
    const path = try allocator.dupe(u8, "lib/lib.zig");
    const source_z = try allocator.dupeZ(u8, source);
    const ast = try std.zig.Ast.parse(allocator, source_z, .zig);

    var files: core.SourceFiles = .{ .items = .empty };
    try files.items.append(allocator, .{
        .path = path,
        .source = source_z,
        .ast = ast,
    });

    var ctx: core.Context = .{
        .arena = allocator,
        .config = .{ .mode = .fix },
    };

    try lintDir(&ctx, "lib/lib.zig", "lib", "lib", &.{ "lib/lib.zig", "lib/a.zig" }, &files);

    try std.testing.expectEqual(0, ctx.diagnostics.items.len);
    try std.testing.expect(files.items.items[0].has_changes);
    try std.testing.expectEqualStrings(expected, files.items.items[0].source);
}

test "canonical block emits skip comments" {
    const allocator = std.heap.page_allocator;
    const source =
        \\comptime {
        \\    if (@import("builtin").is_test) {
        \\        // lint: skip b.zig
        \\    }
        \\}
        \\
    ;
    const skipped = try skippedTestInclusionImports(allocator, source);
    try std.testing.expectEqual(1, skipped.items.len);
    try std.testing.expectEqualStrings("b.zig", skipped.items[0]);
    const expected_raw = [_][]const u8{ "a.zig", "b.zig" };

    const block = try canonicalTestBlock(allocator, &expected_raw, skipped.items, .replace);
    try std.testing.expect(std.mem.indexOf(u8, block, "@import(\"a.zig\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, block, "@import(\"b.zig\")") == null);
    try std.testing.expect(
        std.mem.indexOf(u8, block, "// lint: skip b.zig") != null,
    );
}

test "insert offset skips leading imports" {
    const source =
        \\const std = @import("std");
        \\const lib = @import("lib.zig");
        \\
        \\pub const value = 1;
        \\
    ;
    const expected = std.mem.indexOf(u8, source, "pub const") orelse
        return error.TestUnexpectedResult;
    const offset = testBlockInsertOffset(source);
    try std.testing.expectEqual(expected, offset);
}
