const std = @import("std");
const sbpf = @import("sbpf.zig");
const exe = @import("executable.zig");

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

pub const AccessError = error{ StackAccessViolation, AccessViolation };
pub const RegionError = AccessError || error{InvalidMemoryRegion};
pub const InitError = error{InvalidMemoryRegion};

pub const MemoryMap = union(enum) {
    aligned: AlignedMemoryMap,
    unaligned: UnalignedMemoryMap,

    pub fn init(
        allocator: std.mem.Allocator,
        regions: []const Region,
        version: sbpf.Version,
        config: *const exe.Config,
    ) (error{OutOfMemory} || InitError)!MemoryMap {
        return if (config.aligned_memory_mapping)
            .{ .aligned = try AlignedMemoryMap.init(regions, version, config) }
        else
            .{ .unaligned = try UnalignedMemoryMap.init(allocator, regions, version, config) };
    }

    pub fn deinit(self: *const MemoryMap, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .aligned => {},
            .unaligned => |unaligned| unaligned.deinit(allocator),
        }
    }

    fn find_region(
        self: MemoryMap,
        vm_addr: u64,
    ) ?Region {
        return switch (self) {
            .aligned => |aligned| aligned.find_region(vm_addr),
            .unaligned => |unaligned| unaligned.find_region(vm_addr),
        };
    }

    pub fn region(
        self: MemoryMap,
        comptime access_type: MemoryState,
        vm_addr: u64,
    ) RegionError!Region {
        if (self.find_region(vm_addr)) |found_region| {
            if (found_region.isValidAccess(access_type, vm_addr)) return found_region;
        }

        const version, const config = switch (self) {
            inline else => |map| .{ map.version, map.config },
        };
        return accessViolation(vm_addr, version, config);
    }

    pub fn vmap(
        self: MemoryMap,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
    ) AccessError!state.Slice() {
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
    ) ?state.Slice() {
        if (vm_addr < self.vm_addr_start) return null;

        const host_slice = self.hostSlice(state) orelse return null;
        const begin_offset = vm_addr -| self.vm_addr_start;
        if (begin_offset +| len <= host_slice.len) return host_slice[begin_offset..][0..len];

        return null;
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

    fn isValidAccess(self: Region, access_type: MemoryState, vm_addr: u64) bool {
        if (access_type == .mutable and self.host_memory == .constant) return false;
        if (vm_addr >= self.vm_addr_end) return false;
        if (vm_addr < self.vm_addr_start) return false;

        return true;
    }
};

pub const AlignedMemoryMap = struct {
    regions: []const Region,
    version: sbpf.Version,
    config: *const exe.Config,

    fn init(
        regions: []const Region,
        version: sbpf.Version,
        config: *const exe.Config,
    ) InitError!AlignedMemoryMap {
        for (regions, 1..) |reg, index| {
            if (reg.vm_addr_start >> VIRTUAL_ADDRESS_BITS != index) {
                return error.InvalidMemoryRegion;
            }
        }
        return .{
            .regions = regions,
            .version = version,
            .config = config,
        };
    }

    fn find_region(self: *const AlignedMemoryMap, vm_addr: u64) ?Region {
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
    ) AccessError!state.Slice() {
        const err = accessViolation(vm_addr, self.version, self.config);
        const reg = self.find_region(vm_addr) orelse return err;
        return reg.translate(state, vm_addr, len) orelse return err;
    }
};

fn accessViolation(
    vm_addr: u64,
    version: sbpf.Version,
    config: *const exe.Config,
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

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L183
/// Memory mapping based on eytzinger search.
const UnalignedMemoryMap = struct {
    /// Mapped memory regions
    regions: []Region,
    /// Copy of the regions vm_addr fields to improve cache density
    region_addresses: []u64,
    // Executable sbpf_version
    version: sbpf.Version,
    // VM configuration
    config: *const exe.Config,

    // CoW callback
    //cow_cb: ?MemoryCowCallback,
    // Cache of the last `MappingCache::SIZE` vm_addr => region_index lookups
    //cache: MappingCache,

    fn init(
        allocator: std.mem.Allocator,
        _regions: []const Region,
        version: sbpf.Version,
        config: *const exe.Config,
    ) (error{OutOfMemory} || InitError)!UnalignedMemoryMap {
        const sorted_regions = try allocator.dupe(Region, _regions);
        defer allocator.free(sorted_regions);
        std.mem.sort(Region, sorted_regions, {}, Region.lessThanFn);

        if (Region.regionsOverlap(sorted_regions)) return error.InvalidMemoryRegion;

        const region_addresses = try allocator.alloc(u64, sorted_regions.len);
        errdefer allocator.free(region_addresses);

        const regions = try allocator.alloc(Region, _regions.len);
        errdefer allocator.free(regions);

        var self: UnalignedMemoryMap = .{
            .regions = regions,
            .region_addresses = region_addresses,
            // .cache
            .version = version,
            .config = config,
            // .cow_cb
        };

        _ = self.constructEytzingerOrder(sorted_regions, 0, 0);

        return self;
    }

    fn deinit(self: *const UnalignedMemoryMap, allocator: std.mem.Allocator) void {
        allocator.free(self.regions);
        allocator.free(self.region_addresses);
    }

    // [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L218
    fn constructEytzingerOrder(
        self: UnalignedMemoryMap,
        ascending_regions: []Region,
        _in_index: usize,
        out_index: usize,
    ) usize {
        if (out_index >= ascending_regions.len) return _in_index;

        const in_index = self.constructEytzingerOrder(
            ascending_regions,
            _in_index,
            (out_index *| 2) +| 1,
        );

        {
            self.regions[out_index] = ascending_regions[in_index];
            // agave mutates ascending_regions like this, but there's no reason for it (mem::take).
            // ascending_regions[in_index] = Region.DEFAULT; // agave
        }

        self.region_addresses[out_index] = self.regions[out_index].vm_addr_start;

        return self.constructEytzingerOrder(
            ascending_regions,
            in_index +| 1,
            (out_index *| 2) +| 2,
        );
    }

    // [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L293
    fn find_region(self: *const UnalignedMemoryMap, vm_addr: u64) ?Region {
        // NOTE: agave-like cache unimplemented. Does not seem necessary.

        var index: usize = 1;
        while (index <= self.region_addresses.len) {
            std.debug.assert(index > 0); // safe: index started at 1 and only increases.
            index = (index << 1) + @intFromBool(self.region_addresses[index - 1] <= vm_addr);
        }

        index = std.math.shr(usize, index, @ctz(index) + 1);
        return if (index == 0) null else self.regions[index - 1];
    }

    fn vmap(
        self: UnalignedMemoryMap,
        comptime access_type: MemoryState,
        vm_addr: u64,
        len: u64,
    ) AccessError!access_type.Slice() {
        const err = accessViolation(vm_addr, self.version, self.config);
        const reg = self.find_region(vm_addr) orelse return err;
        return reg.translate(access_type, vm_addr, len) orelse return err;
    }
};
const expectError = std.testing.expectError;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

test "aligned vmap" {
    var program_mem: [4]u8 = .{0xFF} ** 4;
    var stack_mem: [4]u8 = .{0xDD} ** 4;

    const m = try MemoryMap.init(
        std.testing.failing_allocator,
        &.{
            Region.init(.mutable, &program_mem, RODATA_START),
            Region.init(.constant, &stack_mem, STACK_START),
        },
        .v3,
        &exe.Config{},
    );

    try expectEqual(
        program_mem[0..1],
        try m.vmap(.constant, RODATA_START, 1),
    );
    try expectEqual(
        program_mem[0..3],
        try m.vmap(.constant, RODATA_START, 3),
    );
    try expectError(
        error.AccessViolation,
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

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L1240
test "aligned region" {
    var program_mem: [4]u8 = .{0xFF} ** 4;
    var stack_mem: [4]u8 = .{0xDD} ** 4;

    const m = try MemoryMap.init(
        std.testing.failing_allocator,
        &.{
            Region.init(.mutable, &program_mem, RODATA_START),
            Region.init(.constant, &stack_mem, STACK_START),
        },
        .v3,
        &exe.Config{},
    );

    try expectError(error.AccessViolation, m.region(.constant, RODATA_START - 1));
    try expectEqual(&program_mem, (try m.region(.constant, RODATA_START)).hostSlice(.constant));
    try expectEqual(&program_mem, (try m.region(.constant, RODATA_START + 3)).hostSlice(.constant));
    try expectError(error.AccessViolation, m.region(.constant, RODATA_START + 4));
    try expectEqual(error.AccessViolation, m.region(.mutable, STACK_START));
    try expectEqual(&stack_mem, (try m.region(.constant, STACK_START)).hostSlice(.constant));
    try expectEqual(&stack_mem, (try m.region(.constant, STACK_START + 3)).hostSlice(.constant));
    try expectError(error.AccessViolation, m.region(.constant, INPUT_START + 3));
}

test "invalid memory region" {
    var program_mem: [4]u8 = .{0xFF} ** 4;
    var stack_mem: [4]u8 = .{0xDD} ** 4;

    try expectError(
        error.InvalidMemoryRegion,
        MemoryMap.init(
            std.testing.failing_allocator,
            &.{
                Region.init(.constant, &stack_mem, STACK_START),
                Region.init(.mutable, &program_mem, RODATA_START),
            },
            .v0,
            &exe.Config{},
        ),
    );
}

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L1073
test "unaligned map overlap" {
    const allocator = std.testing.allocator;
    const config: exe.Config = .{};

    const mem1: []const u8 = &.{ 1, 2, 3, 4 };
    const mem2: []const u8 = &.{ 5, 6 };

    try std.testing.expectError(
        error.InvalidMemoryRegion,
        UnalignedMemoryMap.init(
            allocator,
            &.{
                Region.init(.constant, mem1, INPUT_START),
                Region.init(.constant, mem2, INPUT_START + mem1.len - 1),
            },
            .v3,
            &config,
        ),
    );

    const map = try UnalignedMemoryMap.init(
        allocator,
        &.{
            Region.init(.constant, mem1, INPUT_START),
            Region.init(.constant, mem2, INPUT_START + mem1.len),
        },
        .v3,
        &config,
    );
    defer map.deinit(allocator);
}

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L1100
test "unaligned map" {
    const allocator = std.testing.allocator;
    const config: exe.Config = .{};

    var mem1 = [_]u8{11};
    const mem2 = [_]u8{ 22, 22 };
    const mem3 = [_]u8{33};
    const mem4 = [_]u8{ 44, 44 };

    const map = try UnalignedMemoryMap.init(
        allocator,
        &.{
            Region.init(.mutable, &mem1, INPUT_START),
            Region.init(.constant, &mem2, INPUT_START + mem1.len),
            Region.init(.constant, &mem3, INPUT_START + mem1.len + mem2.len),
            Region.init(.constant, &mem4, INPUT_START + mem1.len + mem2.len + mem3.len),
        },
        .v3,
        &config,
    );
    defer map.deinit(allocator);

    try expectEqualSlices(u8, &mem1, try map.vmap(.constant, INPUT_START, 1));
    try expectEqualSlices(u8, &mem1, try map.vmap(.mutable, INPUT_START, 1));
    try expectError(error.AccessViolation, map.vmap(.constant, INPUT_START, 2));
    try expectEqualSlices(u8, &mem2, try map.vmap(.constant, INPUT_START + mem1.len, 2));
    try expectEqualSlices(u8, &mem3, try map.vmap(.constant, INPUT_START + mem1.len + mem2.len, 1));
    try expectEqualSlices(
        u8,
        &mem4,
        try map.vmap(.constant, INPUT_START + mem1.len + mem2.len + mem3.len, 2),
    );
    try expectError(
        error.AccessViolation,
        map.vmap(.constant, INPUT_START + mem1.len + mem2.len + mem3.len + mem4.len, 1),
    );
}

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L1180
test "unaligned region" {
    const allocator = std.testing.allocator;
    const config: exe.Config = .{
        .aligned_memory_mapping = false,
    };

    var mem1 = [_]u8{0xFF} ** 4;
    const mem2 = [_]u8{0xDD} ** 4;

    const map = try MemoryMap.init(
        allocator,
        &.{
            Region.init(.mutable, &mem1, INPUT_START),
            Region.init(.constant, &mem2, INPUT_START + 4),
        },
        .v3,
        &config,
    );
    defer map.deinit(allocator);

    try expectError(error.AccessViolation, map.region(.constant, INPUT_START - 1));
    try expectEqual(&mem1, (try map.region(.constant, INPUT_START)).hostSlice(.constant));
    try expectEqual(&mem1, (try map.region(.constant, INPUT_START + 3)).hostSlice(.constant));
    try expectError(error.AccessViolation, map.region(.mutable, INPUT_START + 4));
    try expectEqual(&mem2, (try map.region(.constant, INPUT_START + 4)).hostSlice(.constant));
    try expectEqual(&mem2, (try map.region(.constant, INPUT_START + 7)).hostSlice(.constant));
    try expectError(error.AccessViolation, map.region(.constant, INPUT_START + 8));
}
