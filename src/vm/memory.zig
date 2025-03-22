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
    unaligned: UnalignedMemoryMap,

    pub fn init(regions: []const Region, version: sbpf.Version) !MemoryMap {
        return .{ .aligned = try AlignedMemoryMap.init(regions, version) };
    }

    pub fn region(self: MemoryMap, vm_addr: u64) !Region {
        return switch (self) {
            .aligned => |aligned| aligned.region(vm_addr),
            .unaligned => |unaligned| unaligned.region(vm_addr),
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
            .unaligned => |unaligned| unaligned.vmap(state, vm_addr, len),
        };
    }
};

// better name?
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

    const DEFAULT: Region = .{ // NOTE: this isn't nice, maybe remove
        .host_memory = .{ .constant = &.{} },
        .vm_addr_start = 0,
        .vm_addr_end = 0,
    };

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
    /// Returns null if you're trying to get mutable access to a constant region.
    pub fn hostSlice(self: Region, comptime state: MemoryState) ?state.Slice() {
        return switch (self.host_memory) {
            .constant => |constant| if (state == .mutable) null else constant,
            .mutable => |mutable| mutable,
        };
    }

    fn translate(
        self: Region,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
    ) AccessError!state.Slice() {
        if (vm_addr < self.vm_addr_start) return error.InvalidVirtualAddress;

        const host_slice = try self.hostSlice(state);
        const begin_offset = vm_addr -| self.vm_addr_start;
        if (try std.math.add(u64, begin_offset, len) <= host_slice.len) {
            return host_slice[begin_offset..][0..len];
        }

        return error.InvalidVirtualAddress;
    }

    fn lessThanFn(context: void, lhs: Region, rhs: Region) bool {
        _ = context;
        return lhs.vm_addr_start < rhs.vm_addr_start;
    }

    fn regionsOverlap(sorted_regions: []const Region) bool {
        var iter = std.mem.window(Region, sorted_regions, 2, 1);

        while (iter.next()) |region_pair|
            if (region_pair[0].vm_addr_end > region_pair[1].vm_addr_start)
                return true;

        return false;
    }

    fn isValidAccess(self: Region, access_type: MemoryState) bool {
        return access_type == .constant or self.host_memory == .mutable;
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

    fn region(self: *const AlignedMemoryMap, vm_addr: u64) ?Region {
        const index = vm_addr >> VIRTUAL_ADDRESS_BITS;

        if (index >= 1 and index <= self.regions.len) {
            const reg = self.regions[index - 1];
            if (vm_addr >= reg.vm_addr_start and vm_addr < reg.vm_addr_end) {
                return reg;
            }
        }

        return null;
    }

    fn vmap(
        self: *const AlignedMemoryMap,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
    ) !state.Slice() {
        const err = accessViolation(vm_addr, self.version, self.config);
        const reg = self.region(vm_addr) orelse return err;
        return reg.translate(state, vm_addr, len) catch return err;
    }
};

const AccessError = error{ AccessViolation, StackAccessViolation };

fn accessViolation(
    vm_addr: u64,
    version: sbpf.Version,
    config: *const sbpf.Config,
) AccessError {
    const stack_frame_idx = std.math.divExact(
        u64,
        vm_addr -| STACK_START,
        config.stack_frame_size,
    ) catch 0;

    return if (!version.enableDynamicStackFrames() and stack_frame_idx < config.max_call_depth)
        error.StackAccessViolation
    else
        error.AccessViolation;
}

/// Type of memory access
pub const AccessType = enum { Read, Write };

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L183
/// Memory mapping based on eytzinger search.
const UnalignedMemoryMap = struct {
    /// Mapped memory regions
    regions: []const Region,
    /// Copy of the regions vm_addr fields to improve cache density
    region_addresses: []const u64,
    // Executable sbpf_version
    version: sbpf.Version,
    // VM configuration
    config: *const sbpf.Config,

    // CoW callback
    //cow_cb: ?MemoryCowCallback,
    // Cache of the last `MappingCache::SIZE` vm_addr => region_index lookups
    //cache: MappingCache,
    fn init(allocator: std.mem.Allocator, regions: []Region, version: sbpf.Version) error{OutOfMemory}!UnalignedMemoryMap {
        std.mem.sort(u8, regions, {}, Region.lessThanFn);
        if (Region.regionsOverlap(regions)) return error.InvalidMemoryRegion;

        const region_addresses = try allocator.alloc(u64, regions.len);
        errdefer allocator.free(region_addresses);

        var self: UnalignedMemoryMap = .{
            .regions = regions,
            .region_addresses = region_addresses,
            // .cache
            // .config
            .version = version,
            // .cow_cb
        };

        self.constructEytzingerOrder(regions, 0, 0);

        return self;
    }

    fn constructEytzingerOrder(
        self: UnalignedMemoryMap,
        sorted_regions: []Region,
        _in_index: usize,
        out_index: usize,
    ) usize {
        if (out_index >= sorted_regions.len) return _in_index;

        const in_index = self.constructEytzingerOrder(
            sorted_regions,
            _in_index,
            out_index *| 2 +| 1,
        );

        self.regions[out_index] = sorted_regions[in_index];
        sorted_regions[in_index] = Region.DEFAULT; // no idea why agave does this
        self.region_addresses[out_index] = self.regions[out_index].vm_addr_start;

        return self.constructEytzingerOrder(
            sorted_regions,
            _in_index +| 1,
            out_index *| 2 +| 2,
        );
    }

    fn region(self: *const UnalignedMemoryMap, vm_addr: u64) ?Region {
        // NOTE: agave-like cache unimplemented. Not sure if necessary

        var index: usize = 1;
        while (index <= self.region_addresses.len) {
            index = (index << 1) + @intFromBool(self.region_addresses[index - 1] <= vm_addr);
        }

        index >>= @ctz(index) + 1;
        if (index == 0) return null;

        return self.regions[index - 1];
    }

    fn vmap(
        self: UnalignedMemoryMap,
        comptime access_type: MemoryState,
        vm_addr: u64,
    ) AccessError!access_type.Slice() {
        const err = accessViolation(vm_addr, self.version, self.config);
        const reg = self.region(vm_addr) orelse return err;
        return reg.translate(access_type) orelse return err;
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
        (try m.region(RODATA_START)).hostSlice(.constant),
    );
    try expectEqual(
        &program_mem,
        (try m.region(RODATA_START + 3)).hostSlice(.constant),
    );
    try expectError(
        error.AccessNotMapped,
        m.region(RODATA_START + 4),
    );

    try expectError(
        error.AccessViolation,
        (try m.region(STACK_START)).hostSlice(.mutable),
    );
    try expectEqual(
        &stack_mem,
        (try m.region(STACK_START)).hostSlice(.constant),
    );
    try expectEqual(
        &stack_mem,
        (try m.region(STACK_START + 3)).hostSlice(.constant),
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
