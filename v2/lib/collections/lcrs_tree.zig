const std = @import("std");
const collections = @import("../collections.zig");

const Id = collections.Id;

/// An implementation of a left-child right-sibling tree.
/// NOTE: this implementation is not atomic, but could be made atomic with minimal effort
pub fn LCRSTree(Node: type, IdInt: type) type {
    const needed_fields: []const []const u8 = &.{ "parent", "child", "sibling" };

    const NodeId = Id(IdInt);

    for (needed_fields) |field| {
        if (!@hasField(Node, field)) {
            @compileLog("missing field", Node, field);
            continue;
        }
        if (@FieldType(Node, field) != NodeId)
            @compileLog("incorrect type", Node, field);
    }

    return extern struct {
        len: IdInt,
        buf: [*]Node,

        const Self = @This();

        fn ptrToIdx(self: *const Self, node: *Node) NodeId {
            const idx = @as([*]Node, node[0..1]) - self.buf;
            return @enumFromInt(idx);
        }

        pub fn linkOrphaned(self: *const Self, parent: *Node, orphan: *Node) void {
            std.debug.assert(orphan.parent == .null);
            std.debug.assert(orphan.sibling == .null);

            orphan.parent = self.ptrToIdx(parent);

            if (parent.child == .null) {
                parent.child = self.ptrToIdx(orphan);
            } else {
                orphan.sibling = parent.child;
                parent.child = self.ptrToIdx(orphan);
            }
        }
    };
}
