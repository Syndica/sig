const std = @import("std");
const sbpf = @import("sbpf.zig");

/// Virtual address of the bytecode region (in SBPFv3)
pub const BYTECODE_START: u64 = 0x000000000;
/// Virtual address of the readonly data region (also contains the bytecode until SBPFv3)
pub const RODATA_START: u64 = 0x100000000;
/// Virtual address of the stack region
pub const STACK_START: u64 = 0x200000000;
/// Virtual address of the heap region
pub const HEAP_START: u64 = 0x300000000;
/// Virtual address of the input region
pub const INPUT_START: u64 = 0x400000000;
const VIRTUAL_ADDRESS_BITS = 32;

pub const MemoryMap = union(enum) {
    aligned: AlignedMemoryMap,
    // TODO: unaligned memory map?

    pub fn init(regions: []const Region, version: sbpf.Version) !MemoryMap {
        return .{ .aligned = try AlignedMemoryMap.init(regions, version) };
    }

    pub fn region(self: MemoryMap, vm_addr: u64) !Region {
        return switch (self) {
            .aligned => |aligned| aligned.region(vm_addr),
        };
    }

    pub fn vmap(
        self: MemoryMap,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
    ) !state.Slice() {
        return switch (self) {
            .aligned => |aligned| aligned.vmap(state, vm_addr, len),
        };
    }
};

pub const MemoryState = enum {
    mutable,
    constant,

    fn Slice(self: MemoryState) type {
        return switch (self) {
            .constant => []const u8,
            .mutable => []u8,
        };
    }

    fn Many(self: MemoryState) type {
        return switch (self) {
            .constant => [*]const u8,
            .mutable => [*]u8,
        };
    }
};

const HostMemory = union(MemoryState) {
    mutable: []u8,
    constant: []const u8,

    fn getSlice(self: HostMemory, comptime state: MemoryState) !state.Slice() {
        if (self != state) return error.AccessViolation;
        return @field(self, @tagName(state));
    }
};

pub const Region = struct {
    host_memory: HostMemory,
    vm_addr_start: u64,
    vm_addr_end: u64,

    pub fn init(comptime state: MemoryState, slice: state.Slice(), vm_addr: u64) Region {
        const vm_addr_end = vm_addr +| slice.len;

        return .{
            .host_memory = @unionInit(HostMemory, @tagName(state), slice),
            .vm_addr_start = vm_addr,
            .vm_addr_end = vm_addr_end,
        };
    }

    /// Get the underlying host slice of memory.
    ///
    /// Returns an error if you're trying to get mutable access to a constant region.
    pub fn getSlice(self: Region, comptime state: MemoryState) !state.Slice() {
        return switch (state) {
            .constant => switch (self.host_memory) {
                .constant => |constant| constant,
                .mutable => |mutable| mutable,
            },
            .mutable => switch (self.host_memory) {
                .constant => return error.AccessViolation,
                .mutable => |mutable| mutable,
            },
        };
    }

    fn translate(
        self: Region,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
    ) !state.Slice() {
        if (vm_addr < self.vm_addr_start) return error.InvalidVirtualAddress;

        const host_slice = try self.getSlice(state);
        const begin_offset = vm_addr -| self.vm_addr_start;
        if (try std.math.add(u64, begin_offset, len) <= host_slice.len) {
            return host_slice[begin_offset..][0..len];
        }

        return error.VirtualAccessTooLong;
    }
};

const AlignedMemoryMap = struct {
    regions: []const Region,
    version: sbpf.Version,

    fn init(regions: []const Region, version: sbpf.Version) !AlignedMemoryMap {
        for (regions, 1..) |reg, index| {
            if (reg.vm_addr_start >> VIRTUAL_ADDRESS_BITS != index) {
                return error.InvalidMemoryRegion;
            }
        }

        return .{
            .regions = regions,
            .version = version,
        };
    }

    fn region(self: *const AlignedMemoryMap, vm_addr: u64) !Region {
        const index = vm_addr >> VIRTUAL_ADDRESS_BITS;

        if (index >= 1 and index <= self.regions.len) {
            const reg = self.regions[index - 1];
            if (vm_addr >= reg.vm_addr_start and vm_addr < reg.vm_addr_end) {
                return reg;
            }
        }

        return error.AccessNotMapped;
    }

    fn vmap(
        self: *const AlignedMemoryMap,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
    ) !state.Slice() {
        const reg = try self.region(vm_addr);
        return reg.translate(state, vm_addr, len);
    }
};

const expectError = std.testing.expectError;
const expectEqual = std.testing.expectEqual;

test "aligned vmap" {
    var program_mem: [4]u8 = .{0xFF} ** 4;
    var stack_mem: [4]u8 = .{0xDD} ** 4;

    const m = try MemoryMap.init(&.{
        Region.init(.mutable, &program_mem, RODATA_START),
        Region.init(.constant, &stack_mem, STACK_START),
    }, .v0);

    try expectEqual(
        program_mem[0..1],
        try m.vmap(.constant, RODATA_START, 1),
    );
    try expectEqual(
        program_mem[0..3],
        try m.vmap(.constant, RODATA_START, 3),
    );
    try expectError(
        error.VirtualAccessTooLong,
        m.vmap(.constant, RODATA_START, 5),
    );

    try expectError(
        error.AccessViolation,
        m.vmap(.mutable, STACK_START, 2),
    );
    try expectError(
        error.AccessViolation,
        m.vmap(.mutable, STACK_START, 5),
    );
    try expectEqual(
        stack_mem[1..3],
        try m.vmap(.constant, STACK_START + 1, 2),
    );
}

test "aligned region" {
    var program_mem: [4]u8 = .{0xFF} ** 4;
    var stack_mem: [4]u8 = .{0xDD} ** 4;

    const m = try MemoryMap.init(&.{
        Region.init(.mutable, &program_mem, RODATA_START),
        Region.init(.constant, &stack_mem, STACK_START),
    }, .v0);

    try expectError(
        error.AccessNotMapped,
        m.region(RODATA_START - 1),
    );
    try expectEqual(
        &program_mem,
        (try m.region(RODATA_START)).getSlice(.constant),
    );
    try expectEqual(
        &program_mem,
        (try m.region(RODATA_START + 3)).getSlice(.constant),
    );
    try expectError(
        error.AccessNotMapped,
        m.region(RODATA_START + 4),
    );

    try expectError(
        error.AccessViolation,
        (try m.region(STACK_START)).getSlice(.mutable),
    );
    try expectEqual(
        &stack_mem,
        (try m.region(STACK_START)).getSlice(.constant),
    );
    try expectEqual(
        &stack_mem,
        (try m.region(STACK_START + 3)).getSlice(.constant),
    );
    try expectError(
        error.AccessNotMapped,
        m.region(INPUT_START + 3),
    );
}

test "invalid memory region" {
    var program_mem: [4]u8 = .{0xFF} ** 4;
    var stack_mem: [4]u8 = .{0xDD} ** 4;

    try expectError(
        error.InvalidMemoryRegion,
        MemoryMap.init(&.{
            Region.init(.constant, &stack_mem, STACK_START),
            Region.init(.mutable, &program_mem, RODATA_START),
        }, .v0),
    );
}
