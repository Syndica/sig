//! Finds unused private `const`, `var`, and `fn` declarations.
//!
//! A declaration is used when its identifier appears outside its own declaration. This token-based
//! heuristic can have false negatives when an unrelated identifier has the same name, but it should
//! not have false positives. Public and exported declarations are kept. A declaration can opt out
//! with `// lint: allow_unused` on the line above it. Fix mode removes unused declarations
//! repeatedly so aliases that become unused after earlier removals are removed too.

const std = @import("std");

const core = @import("core.zig");

const Allocator = std.mem.Allocator;

const allow_unused_comment = "// lint: allow_unused";

const DeclarationCandidate = struct {
    line: usize,
    column: usize,
    removal: Removal,
};

const Removal = union(enum) {
    range: RemovalRange,
    blocked: UnfixableReason,
};

const RemovalRange = struct {
    start: usize,
    end: usize,
};

const UnfixableReason = enum {
    preceding_comment,
    not_isolated,
};

pub fn lint(ctx: *core.Context, file: *core.SourceFile) !void {
    switch (ctx.config.mode) {
        .check => {
            var candidates: std.ArrayList(DeclarationCandidate) = .empty;
            defer candidates.deinit(ctx.allocator);
            try findAndSortUnusedDeclarations(
                ctx.allocator,
                file.source,
                &file.ast,
                &candidates,
            );
            try addUnusedDeclarationDiagnostics(ctx, file, candidates.items);
        },
        .fix => {
            while (true) {
                var candidates: std.ArrayList(DeclarationCandidate) = .empty;
                defer candidates.deinit(ctx.allocator);
                try findAndSortUnusedDeclarations(
                    ctx.allocator,
                    file.source,
                    &file.ast,
                    &candidates,
                );
                if (candidates.items.len == 0) {
                    break;
                }
                const fixed = try applySortedDeclarationRemovals(
                    ctx.allocator,
                    file.source,
                    candidates.items,
                ) orelse {
                    try addUnusedDeclarationDiagnostics(ctx, file, candidates.items);
                    break;
                };
                try file.replaceSource(ctx.allocator, fixed, "unused_declarations");
            }
        },
    }
}

fn addUnusedDeclarationDiagnostics(
    ctx: *core.Context,
    file: *const core.SourceFile,
    candidates: []const DeclarationCandidate,
) !void {
    for (candidates) |candidate| {
        const unused_message = "unused declaration";
        const message = switch (ctx.config.mode) {
            .check => unused_message,
            .fix => switch (candidate.removal) {
                .range => unused_message,
                .blocked => |reason| unfixableMessage(reason),
            },
        };
        try ctx.addDiagnostic(
            file.path,
            candidate.line,
            candidate.column,
            .unused_declarations,
            message,
        );
    }
}

fn unfixableMessage(reason: UnfixableReason) []const u8 {
    return switch (reason) {
        .preceding_comment => "unused declaration not fixed: preceding comment may document it",
        .not_isolated => "unused declaration not fixed: not isolated on its own line",
    };
}

fn findAndSortUnusedDeclarations(
    allocator: Allocator,
    source: []const u8,
    ast: *const std.zig.Ast,
    candidates: *std.ArrayList(DeclarationCandidate),
) !void {
    var identifier_counts = try collectIdentifierCounts(allocator, ast);
    defer identifier_counts.deinit();

    var node_index: usize = 0;
    while (node_index < ast.nodes.len) : (node_index += 1) {
        const node: std.zig.Ast.Node.Index = @enumFromInt(node_index);
        const decl = declaration(ast, node) orelse continue;
        if (hasAllowUnusedComment(source, ast.tokenStart(decl.first_token))) continue;

        // Identifier counts ignore comments and strings. Declaration range count is subtracted so
        // declaration name does not count itself.
        if (identifierUsedOutsideDecl(
            ast,
            &identifier_counts,
            decl.name,
            decl.first_token,
            decl.last_token,
        )) continue;

        const loc = core.lineColumn(source, ast.tokenStart(decl.name_token));
        try candidates.append(allocator, .{
            .line = loc.line,
            .column = loc.column,
            .removal = declarationRemoval(source, ast, decl.first_token, decl.last_token),
        });
    }

    sortDeclarationCandidates(candidates.items);
}

const Declaration = struct {
    name_token: std.zig.Ast.TokenIndex,
    name: []const u8,
    first_token: std.zig.Ast.TokenIndex,
    last_token: std.zig.Ast.TokenIndex,
};

fn declaration(ast: *const std.zig.Ast, node: std.zig.Ast.Node.Index) ?Declaration {
    return variableDeclaration(ast, node) orelse functionDeclaration(ast, node);
}

fn variableDeclaration(
    ast: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
) ?Declaration {
    const var_decl = ast.fullVarDecl(node) orelse return null;
    if (var_decl.visib_token != null) return null;
    if (var_decl.extern_export_token) |token| {
        if (ast.tokenTag(token) == .keyword_export) return null;
    }
    // In normal Zig variable declarations, identifier token follows `const` or `var` token.
    const name_token = var_decl.ast.mut_token + 1;
    if (ast.tokenTag(name_token) != .identifier) return null;
    return .{
        .name_token = name_token,
        .name = ast.tokenSlice(name_token),
        .first_token = var_decl.firstToken(),
        .last_token = ast.lastToken(node),
    };
}

fn functionDeclaration(
    ast: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
) ?Declaration {
    switch (ast.nodeTag(node)) {
        .fn_decl => {},
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        => {
            const token_after_proto = ast.lastToken(node) + 1;
            if (token_after_proto >= ast.tokens.len) return null;
            if (ast.tokenTag(token_after_proto) != .semicolon) return null;
        },
        else => return null,
    }

    var buffer: [1]std.zig.Ast.Node.Index = undefined;
    const fn_proto = ast.fullFnProto(&buffer, node) orelse return null;
    if (fn_proto.visib_token != null) return null;
    if (fn_proto.extern_export_inline_token) |token| {
        if (ast.tokenTag(token) == .keyword_export) return null;
    }
    const name_token = fn_proto.name_token orelse return null;
    return .{
        .name_token = name_token,
        .name = ast.tokenSlice(name_token),
        .first_token = fn_proto.firstToken(),
        .last_token = ast.lastToken(node),
    };
}

fn declarationRemoval(
    source: []const u8,
    ast: *const std.zig.Ast,
    first: std.zig.Ast.TokenIndex,
    last: std.zig.Ast.TokenIndex,
) Removal {
    const token_start = ast.tokenStart(first);
    if (previousLineComment(source, token_start)) {
        return .{ .blocked = .preceding_comment };
    }
    var end_token = last;
    const token_after_last = last + 1;
    if (token_after_last < ast.tokens.len and ast.tokenTag(token_after_last) == .semicolon) {
        end_token = token_after_last;
    }
    const token_end = ast.tokenStart(end_token) + ast.tokenSlice(end_token).len;
    const line_start = core.lineStart(source, token_start);
    const line_end = core.lineEndIncludingNewline(source, token_end);
    if (!isWhitespace(source[line_start..token_start]) or
        !isWhitespace(source[token_end..line_end]))
    {
        return .{ .blocked = .not_isolated };
    }
    return .{ .range = .{ .start = line_start, .end = line_end } };
}

fn hasAllowUnusedComment(source: []const u8, token_start: usize) bool {
    const previous_line = previousLine(source, token_start) orelse return false;
    return std.mem.eql(u8, previous_line, allow_unused_comment);
}

fn previousLineComment(source: []const u8, token_start: usize) bool {
    const previous_line = previousLine(source, token_start) orelse return false;
    return std.mem.startsWith(u8, previous_line, "//");
}

fn previousLine(source: []const u8, token_start: usize) ?[]const u8 {
    const line_start = core.lineStart(source, token_start);
    if (line_start == 0) return null;
    const previous_line_end = line_start - 1;
    const previous_line_start = core.lineStart(source, previous_line_end);
    return std.mem.trim(u8, source[previous_line_start..previous_line_end], " \t\r");
}

fn isWhitespace(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (!std.ascii.isWhitespace(byte)) return false;
    }
    return true;
}

fn sortDeclarationCandidates(candidates: []DeclarationCandidate) void {
    std.mem.sort(DeclarationCandidate, candidates, {}, struct {
        fn lessThan(_: void, a: DeclarationCandidate, b: DeclarationCandidate) bool {
            if (a.line == b.line) return a.column < b.column;
            return a.line < b.line;
        }
    }.lessThan);
}

fn collectIdentifierCounts(
    allocator: Allocator,
    ast: *const std.zig.Ast,
) !std.StringHashMap(usize) {
    var counts = std.StringHashMap(usize).init(allocator);
    errdefer counts.deinit();

    var token: std.zig.Ast.TokenIndex = 0;
    while (token < ast.tokens.len) : (token += 1) {
        if (ast.tokenTag(token) != .identifier) continue;
        const name = ast.tokenSlice(token);
        const entry = try counts.getOrPut(name);
        if (entry.found_existing) {
            entry.value_ptr.* += 1;
        } else {
            entry.value_ptr.* = 1;
        }
    }

    return counts;
}

fn identifierUsedOutsideDecl(
    ast: *const std.zig.Ast,
    identifier_counts: *const std.StringHashMap(usize),
    name: []const u8,
    first: std.zig.Ast.TokenIndex,
    last: std.zig.Ast.TokenIndex,
) bool {
    const total_count = identifier_counts.get(name) orelse return false;
    var declaration_count: usize = 0;
    var token = first;
    while (token <= last) : (token += 1) {
        if (ast.tokenTag(token) != .identifier) continue;
        if (std.mem.eql(u8, ast.tokenSlice(token), name)) declaration_count += 1;
    }
    return total_count > declaration_count;
}

/// Applies declaration removals to source. Note the removals must be sorted.
fn applySortedDeclarationRemovals(
    allocator: Allocator,
    source: []const u8,
    candidates: []const DeclarationCandidate,
) !?[:0]u8 {
    var edits: std.ArrayList(core.Edit) = .empty;
    defer edits.deinit(allocator);
    var cursor: usize = 0;
    for (candidates) |candidate| {
        const range = switch (candidate.removal) {
            .range => |range| range,
            .blocked => continue,
        };
        if (range.start < cursor) continue;
        try edits.append(allocator, .{
            .start = range.start,
            .end = range.end,
            .replacement = "",
        });
        cursor = range.end;
    }
    if (edits.items.len == 0) return null;
    return try core.applySortedEdits(allocator, source, edits.items);
}

fn findUnusedDeclarationsInSource(
    allocator: Allocator,
    source: [:0]const u8,
    candidates: *std.ArrayList(DeclarationCandidate),
) !void {
    var ast = try std.zig.Ast.parse(allocator, source, .zig);
    defer ast.deinit(allocator);
    if (ast.errors.len != 0) return error.ParseError;
    try findAndSortUnusedDeclarations(allocator, source, &ast, candidates);
}

test "detects unused declarations through token usage" {
    const allocator = std.testing.allocator;
    const source =
        \\const used = @import("used.zig");
        \\const unused = @import("unused.zig");
        \\const alias = used.Value;
        \\const output = alias;
        \\// unused in comment
        \\const text = "unused";
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(3, candidates.items.len);
    try std.testing.expectEqual(2, candidates.items[0].line);
    try std.testing.expectEqual(7, candidates.items[0].column);
    try std.testing.expectEqual(4, candidates.items[1].line);
    try std.testing.expectEqual(6, candidates.items[2].line);
}

test "reports parse errors" {
    const allocator = std.testing.allocator;
    const source =
        \\const broken = ;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try std.testing.expectError(
        error.ParseError,
        findUnusedDeclarationsInSource(allocator, source, &candidates),
    );
}

test "detects unused const var and fn declarations" {
    const allocator = std.testing.allocator;
    const source =
        \\var mutable = @import("mutable.zig");
        \\const number = 1;
        \\const field = config.value;
        \\fn foo() void {}
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(4, candidates.items.len);
    try std.testing.expectEqual(1, candidates.items[0].line);
    try std.testing.expectEqual(2, candidates.items[1].line);
    try std.testing.expectEqual(3, candidates.items[2].line);
    try std.testing.expectEqual(4, candidates.items[3].line);
}

test "keeps used private functions and public declarations" {
    const allocator = std.testing.allocator;
    const source =
        \\fn used() void {}
        \\fn unused() void {}
        \\pub fn public() void {}
        \\export fn exported() void {}
        \\pub fn entry() void {
        \\    used();
        \\}
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(2, candidates.items[0].line);
}

test "detects nested unused declarations in private containers" {
    const allocator = std.testing.allocator;
    const source =
        \\const S = struct {
        \\    const used = 1;
        \\    const unused = 2;
        \\    var unused_var: u32 = 3;
        \\    fn unusedFn() void {}
        \\    pub const public = 4;
        \\    pub fn get() u32 {
        \\        return used;
        \\    }
        \\};
        \\pub const output = S.get();
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(3, candidates.items.len);
    try std.testing.expectEqual(3, candidates.items[0].line);
    try std.testing.expectEqual(4, candidates.items[1].line);
    try std.testing.expectEqual(5, candidates.items[2].line);
}

test "detects private members in public containers" {
    const allocator = std.testing.allocator;
    const source =
        \\pub const S = struct {
        \\    const unused = 1;
        \\    var unused_var: u32 = 3;
        \\    fn unusedFn() void {}
        \\};
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(3, candidates.items.len);
    try std.testing.expectEqual(2, candidates.items[0].line);
    try std.testing.expectEqual(3, candidates.items[1].line);
    try std.testing.expectEqual(4, candidates.items[2].line);
}

test "ignores container fields" {
    const allocator = std.testing.allocator;
    const source =
        \\const S = struct {
        \\    field: u32,
        \\    other: bool = false,
        \\};
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(1, candidates.items[0].line);
}

test "allows unused declarations with lint comment" {
    const allocator = std.testing.allocator;
    const source =
        \\// lint: allow_unused
        \\const allowed = 1;
        \\// lint: allow_unused
        \\var allowed_var: u32 = 2;
        \\// lint: allow_unused
        \\fn allowedFn() void {}
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(0, candidates.items.len);
}

test "lint comment match is exact" {
    const allocator = std.testing.allocator;
    const source =
        \\// TODO: later add // lint: allow_unused here
        \\const still_unused = 1;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(2, candidates.items[0].line);
}

test "detects unused field-chain aliases" {
    const allocator = std.testing.allocator;
    const source =
        \\const std = @import("std");
        \\const fmt = std.fmt;
        \\const Writer = std.io.Writer;
        \\const Foo = @import("foo.zig").Foo;
        \\const Bar = @import("foo.zig").nested.Bar;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(4, candidates.items.len);
    try std.testing.expectEqual(2, candidates.items[0].line);
    try std.testing.expectEqual(3, candidates.items[1].line);
    try std.testing.expectEqual(4, candidates.items[2].line);
    try std.testing.expectEqual(5, candidates.items[3].line);
}

test "detects unused transitive aliases" {
    const allocator = std.testing.allocator;
    const source =
        \\const std = @import("std");
        \\const fmt = std.fmt;
        \\const Writer = fmt.Writer;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(3, candidates.items[0].line);
}

test "detects unused out-of-order aliases" {
    const allocator = std.testing.allocator;
    const source =
        \\const Writer = fmt.Writer;
        \\const fmt = std.fmt;
        \\const std = @import("std");
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(1, candidates.items[0].line);
}

test "detects unused call declarations" {
    const allocator = std.testing.allocator;
    const source =
        \\const std = @import("std");
        \\const T = std.BoundedArray(u8, 10);
        \\const U = @import("foo.zig").Foo();
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(2, candidates.items.len);
    try std.testing.expectEqual(2, candidates.items[0].line);
    try std.testing.expectEqual(3, candidates.items[1].line);
}

test "fix removes cascading aliases" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const source =
        \\const Writer = fmt.Writer;
        \\const fmt = std.fmt;
        \\const alias = std;
        \\const std = @import("std");
        \\
    ;
    try tmp.dir.writeFile(.{ .sub_path = "unused_declarations_fix.zig", .data = source });
    const path = try tmp.dir.realpathAlloc(allocator, "unused_declarations_fix.zig");
    defer allocator.free(path);

    var ctx = core.Context{
        .allocator = allocator,
        .config = .{ .mode = .fix },
    };
    defer ctx.deinit();

    var file = try core.SourceFile.readAndParse(allocator, path);
    defer file.deinit(allocator);

    try lint(&ctx, &file);

    try std.testing.expect(file.has_changes);
    try std.testing.expectEqualStrings("", file.source);
    try std.testing.expectEqual(0, file.ast.errors.len);

    const unchanged = try std.fs.cwd().readFileAlloc(allocator, path, core.max_source_file_size);
    defer allocator.free(unchanged);
    try std.testing.expectEqualStrings(source, unchanged);

    try file.writeIfChanged();

    const fixed = try std.fs.cwd().readFileAlloc(allocator, path, core.max_source_file_size);
    defer allocator.free(fixed);
    try std.testing.expectEqualStrings("", fixed);
}

test "fix removes clean nested declarations" {
    const allocator = std.testing.allocator;
    const source =
        \\const S = struct {
        \\    const unused = 1;
        \\    pub const kept = 2;
        \\};
        \\pub const x = S.kept;
        \\
    ;
    const expected =
        \\const S = struct {
        \\    pub const kept = 2;
        \\};
        \\pub const x = S.kept;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(.range, std.meta.activeTag(candidates.items[0].removal));
    const fixed = (try applySortedDeclarationRemovals(allocator, source, candidates.items)).?;
    defer allocator.free(fixed);
    try std.testing.expectEqualStrings(expected, fixed);
}

test "fix removes unused functions" {
    const allocator = std.testing.allocator;
    const source =
        \\fn unused() void {
        \\    const x = 1;
        \\    _ = x;
        \\}
        \\pub const kept = 1;
        \\
    ;
    const expected =
        \\pub const kept = 1;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(.range, std.meta.activeTag(candidates.items[0].removal));
    const fixed = (try applySortedDeclarationRemovals(allocator, source, candidates.items)).?;
    defer allocator.free(fixed);
    try std.testing.expectEqualStrings(expected, fixed);
}

test "fix removes multiline imports" {
    const allocator = std.testing.allocator;
    const source =
        \\const unused =
        \\    @import("unused.zig");
        \\pub const kept = 1;
        \\
    ;
    const expected =
        \\pub const kept = 1;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(.range, std.meta.activeTag(candidates.items[0].removal));
    const fixed = (try applySortedDeclarationRemovals(allocator, source, candidates.items)).?;
    defer allocator.free(fixed);
    try std.testing.expectEqualStrings(expected, fixed);
}

test "fix skips compact nested declarations" {
    const allocator = std.testing.allocator;
    const source =
        \\const S = struct { const unused = 1; pub const kept = 2; };
        \\pub const x = S.kept;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(.blocked, std.meta.activeTag(candidates.items[0].removal));
    const fixed = try applySortedDeclarationRemovals(allocator, source, candidates.items);
    try std.testing.expectEqual(null, fixed);
}

test "fix removes unused single line container before blocked nested declarations" {
    const allocator = std.testing.allocator;
    const source = "const S = struct { const a = 1; const b = 2; };\n";

    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(3, candidates.items.len);
    try std.testing.expectEqual(.range, std.meta.activeTag(candidates.items[0].removal));
    try std.testing.expectEqual(.blocked, std.meta.activeTag(candidates.items[1].removal));
    try std.testing.expectEqual(.blocked, std.meta.activeTag(candidates.items[2].removal));

    const fixed = (try applySortedDeclarationRemovals(allocator, source, candidates.items)).?;
    defer allocator.free(fixed);
    try std.testing.expectEqualStrings("", fixed);
}

test "fix skips declarations with preceding comment" {
    const allocator = std.testing.allocator;
    const source =
        \\// keep this note
        \\const unused = 1;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    try std.testing.expectEqual(.blocked, std.meta.activeTag(candidates.items[0].removal));
    const fixed = try applySortedDeclarationRemovals(allocator, source, candidates.items);
    try std.testing.expectEqual(null, fixed);
}

test "fix reports declarations it cannot remove" {
    const allocator = std.testing.allocator;
    const source =
        \\// keep this note
        \\const unused = 1;
        \\
    ;
    const path = try allocator.dupe(u8, "lib/example.zig");
    errdefer allocator.free(path);
    const source_z = try allocator.dupeZ(u8, source);
    errdefer allocator.free(source_z);
    var ast = try std.zig.Ast.parse(allocator, source_z, .zig);
    errdefer ast.deinit(allocator);
    var file: core.SourceFile = .{ .path = path, .source = source_z, .ast = ast };
    defer file.deinit(allocator);

    var ctx: core.Context = .{ .allocator = allocator, .config = .{ .mode = .fix } };
    defer ctx.deinit();

    try lint(&ctx, &file);

    try std.testing.expect(!file.has_changes);
    try std.testing.expectEqual(1, ctx.diagnostics.items.len);
    try std.testing.expectEqualStrings(
        "unused declaration not fixed: preceding comment may document it",
        ctx.diagnostics.items[0].message,
    );
}

test "removes declaration at eof without trailing newline" {
    const allocator = std.testing.allocator;
    const source = "const unused = @import(\"unused.zig\");";
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(1, candidates.items.len);
    const fixed = (try applySortedDeclarationRemovals(allocator, source, candidates.items)).?;
    defer allocator.free(fixed);
    try std.testing.expectEqualStrings("", fixed);
}

test "removes multiple unused declarations" {
    const allocator = std.testing.allocator;
    const source =
        \\const unused_a = @import("a.zig");
        \\const unused_b = @import("b.zig");
        \\const used = @import("used.zig");
        \\pub const x = used.Value;
        \\
    ;
    const expected =
        \\const used = @import("used.zig");
        \\pub const x = used.Value;
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(2, candidates.items.len);
    const fixed = (try applySortedDeclarationRemovals(allocator, source, candidates.items)).?;
    defer allocator.free(fixed);
    try std.testing.expectEqualStrings(expected, fixed);
}

test "keeps public declarations" {
    const allocator = std.testing.allocator;
    const source =
        \\const std = @import("std");
        \\pub const fmt = std.fmt;
        \\pub const exported = @import("exported.zig");
        \\
    ;
    var candidates: std.ArrayList(DeclarationCandidate) = .empty;
    defer candidates.deinit(allocator);
    try findUnusedDeclarationsInSource(allocator, source, &candidates);
    try std.testing.expectEqual(0, candidates.items.len);
}
