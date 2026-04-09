const std = @import("std");
const lib = @import("../lib.zig");

/// An implementation of a left-child right-sibling tree.
/// NOTE: this implementation is not atomic, but could be made atomic with minimal effort
pub fn LCRSTree(Node: type, Context: type) type {
    lib.util.assertInterface(Context, struct {
        pub fn parentOf(ctx: Context, node: *const Node) *Node {
            _ = .{ ctx, node };
            return undefined;
        }
        pub fn childOf(ctx: Context, node: *const Node) *Node {
            _ = .{ ctx, node };
            return undefined;
        }
        pub fn siblingOf(ctx: Context, node: *const Node) *Node {
            _ = .{ ctx, node };
            return undefined;
        }
        pub fn setParent(ctx: Context, node: *Node, parent: *Node) void {
            _ = .{ ctx, node, parent };
        }
        pub fn setChild(ctx: Context, node: *Node, child: *Node) void {
            _ = .{ ctx, node, child };
        }
        pub fn setSibling(ctx: Context, node: *Node, sibling: *Node) void {
            _ = .{ ctx, node, sibling };
        }
    });

    return extern struct {
        pub fn linkOrphaned(ctx: Context, parent: *Node, orphan: *Node) void {
            std.debug.assert(ctx.parentOf(orphan) == null);
            std.debug.assert(ctx.siblingOf(orphan) == null);

            ctx.setParent(orphan, parent);

            if (ctx.childOf(parent)) |child| {
                ctx.setSibling(orphan, child);
                ctx.setChild(parent, orphan);
            } else {
                ctx.setChild(parent, orphan);
            }
        }
    };
}
