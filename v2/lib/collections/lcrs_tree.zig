const std = @import("std");
const lib = @import("../lib.zig");

/// An implementation of a left-child right-sibling tree.
/// NOTE: this implementation is not atomic, but could be made atomic with minimal effort
pub fn LCRSTree(Node: type, Context: type) type {
    lib.util.assertInterface(Context, struct {
        pub fn parentOf(ctx: Context, node: *const Node) ?*Node {
            _ = .{ ctx, node };
            return undefined;
        }
        pub fn childOf(ctx: Context, node: *const Node) ?*Node {
            _ = .{ ctx, node };
            return undefined;
        }
        pub fn siblingOf(ctx: Context, node: *const Node) ?*Node {
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
        pub const parentOf = Context.parentOf;
        pub const childOf = Context.childOf;
        pub const siblingOf = Context.siblingOf;
        pub const setParent = Context.setParent;
        pub const setChild = Context.setChild;
        pub const setSibling = Context.setSibling;

        pub fn linkOrphaned(
            ctx: Context,
            /// In the case of a parent with multiple children, this controls where the new child is
            /// placed. Head is constant time, tail requires looping.
            comptime insert_mode: enum { head, tail },
            parent: *Node,
            orphan: *Node,
        ) void {
            std.debug.assert(ctx.parentOf(orphan) == null);
            std.debug.assert(ctx.siblingOf(orphan) == null);

            ctx.setParent(orphan, parent);

            const child = ctx.childOf(parent) orelse {
                // The parent has no child - this is the typical case for (most? all?) usage.
                ctx.setChild(parent, orphan);
                return;
            };

            switch (insert_mode) {
                .head => { // replace head
                    ctx.setSibling(orphan, child);
                    ctx.setChild(parent, orphan);
                },
                .tail => { // add to tail
                    var tail: ?*Node = child;
                    while (tail) |tail_node| tail = ctx.childOf(tail_node) orelse break;
                    ctx.setSibling(tail.?, orphan);
                },
            }
        }

        pub fn linkNewOrphanedSibling(
            ctx: Context,
            existing_orphan: *Node,
            new_orphan: *Node,
        ) void {
            // Both nodes are orphans, i.e. no parents
            std.debug.assert(ctx.parentOf(existing_orphan) == null);
            std.debug.assert(ctx.parentOf(new_orphan) == null);

            // The existing orphan may already have children, or siblings. The newly inserted one
            // can't.
            std.debug.assert(ctx.siblingOf(new_orphan) == null);
            std.debug.assert(ctx.childOf(new_orphan) == null);

            const tail_sib: *Node = if (ctx.siblingOf(existing_orphan)) |existing_sibling| node: {
                @branchHint(.unlikely);

                // existing_orphan────►sibling_node────►new_orphan
                //         │
                //         ▼
                //      ?child

                var node: *Node = existing_sibling;
                while (ctx.siblingOf(node)) |chained_sibling| : (node = chained_sibling) {}
                break :node node;
            } else
                // existing_orphan────►new_orphan
                //         │
                //         ▼
                //      ?child
                existing_orphan;

            std.debug.assert(ctx.siblingOf(tail_sib) == null);

            ctx.setSibling(tail_sib, new_orphan);
        }
    };
}
