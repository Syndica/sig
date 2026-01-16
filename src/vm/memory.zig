const std = @import("std");
const sig = @import("../sig.zig");
const sbpf = @import("sbpf.zig");
const exe = @import("executable.zig");

const SyscallError = sig.vm.SyscallError;

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
pub const VIRTUAL_ADDRESS_BITS = 32;

pub const AccessError = error{ StackAccessViolation, AccessViolation };
pub const RegionError = AccessError || error{InvalidMemoryRegion};
pub const InitError = error{InvalidMemoryRegion};

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L731
pub const MemoryMap = union(enum) {
    aligned: AlignedMemoryMap,
    unaligned: UnalignedMemoryMap,

    pub fn init(
        allocator: std.mem.Allocator,
        regions: []const Region,
        version: sbpf.Version,
        config: exe.Config,
    ) (error{OutOfMemory} || InitError)!MemoryMap {
        return if (config.aligned_memory_mapping)
            .{ .aligned = try AlignedMemoryMap.init(allocator, regions, version, config) }
        else
            .{ .unaligned = try UnalignedMemoryMap.init(allocator, regions, version, config) };
    }

    pub fn deinit(self: *const MemoryMap, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .aligned => |aligned| aligned.deinit(allocator),
            .unaligned => |unaligned| unaligned.deinit(allocator),
        }
    }

    pub fn findRegion(
        self: MemoryMap,
        vm_addr: u64,
    ) !*Region {
        return switch (self) {
            .aligned => |aligned| try aligned.findRegion(vm_addr),
            .unaligned => |unaligned| try unaligned.findRegion(vm_addr),
        };
    }

    pub fn region(
        self: MemoryMap,
        comptime access_type: MemoryState,
        vm_addr: u64,
    ) RegionError!*Region {
        const found_region = try self.findRegion(vm_addr);
        if (found_region.isValidAccess(access_type, vm_addr)) return found_region;

        const version, const config = switch (self) {
            inline else => |map| .{ map.version, map.config },
        };
        return accessViolation(vm_addr, version, config);
    }

    pub fn store(
        self: MemoryMap,
        comptime T: type,
        vm_addr: u64,
        value: T,
    ) !void {
        return switch (self) {
            .aligned => |aligned| aligned.store(T, vm_addr, value),
            .unaligned => |unaligned| unaligned.store(T, vm_addr, value),
        };
    }

    pub fn load(
        self: MemoryMap,
        comptime T: type,
        vm_addr: u64,
    ) !T {
        return switch (self) {
            .aligned => |aligned| aligned.load(T, vm_addr),
            .unaligned => |unaligned| unaligned.load(T, vm_addr),
        };
    }

    // [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L782
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

    pub fn mapRegion(
        self: MemoryMap,
        comptime state: MemoryState,
        reg: Region,
        vm_addr: u64,
        len: u64,
    ) AccessError!state.Slice() {
        return switch (self) {
            .aligned => |aligned| aligned.mapRegion(state, reg, vm_addr, len),
            .unaligned => |unaligned| unaligned.mapRegion(state, reg, vm_addr, len),
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L604
    pub fn translate(
        memory_map: *const MemoryMap,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
    ) !u64 {
        const slice = try memory_map.vmap(state, vm_addr, len);
        return @intFromPtr(slice.ptr);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L616
    pub fn translateType(
        memory_map: *const MemoryMap,
        comptime T: type,
        comptime state: MemoryState,
        vm_addr: u64,
        check_aligned: bool,
    ) !(switch (state) {
        .mutable => *align(1) T,
        .constant => *align(1) const T,
    }) {
        if (comptime !hasTranslatableRepresentation(T)) {
            @compileError(@typeName(T) ++ " doesn't have a stable layout for translation");
        }

        const host_addr = try memory_map.translate(state, vm_addr, @sizeOf(T));
        if (!check_aligned) {
            return @ptrFromInt(host_addr);
        } else if (host_addr % @alignOf(T) != 0) {
            return SyscallError.UnalignedPointer;
        } else {
            return @ptrFromInt(host_addr);
        }
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L647
    pub fn translateSlice(
        memory_map: *const MemoryMap,
        comptime T: type,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
        check_aligned: bool,
    ) !(switch (state) {
        .mutable => []align(1) T,
        .constant => []align(1) const T,
    }) {
        if (comptime !hasTranslatableRepresentation(T)) {
            @compileError(@typeName(T) ++ " doesn't have a stable layout for translation");
        }

        if (len == 0) {
            return &.{}; // &mut []
        }

        const total_size = len *| @sizeOf(T);
        _ = std.math.cast(isize, total_size) orelse return SyscallError.InvalidLength;

        const host_addr = try memory_map.translate(state, vm_addr, total_size);
        if (check_aligned and host_addr % @alignOf(T) != 0) {
            return SyscallError.UnalignedPointer;
        }

        return switch (state) {
            .mutable => @as([*]align(1) T, @ptrFromInt(host_addr))[0..len],
            .constant => @as([*]align(1) const T, @ptrFromInt(host_addr))[0..len],
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

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L54
pub const Region = struct {
    host_memory: HostMemory,
    vm_addr_start: u64,
    vm_gap_shift: std.math.Log2Int(u64),
    vm_addr_end: u64,

    pub fn init(comptime state: MemoryState, slice: state.Slice(), vm_addr: u64) Region {
        return initGapped(state, slice, vm_addr, 0);
    }

    pub fn initGapped(
        comptime state: MemoryState,
        slice: state.Slice(),
        vm_addr: u64,
        vm_gap_size: u64,
    ) Region {
        const is_gapped = vm_gap_size > 0;
        var vm_gap_shift: u64 = @bitSizeOf(u64) - 1;
        if (is_gapped) {
            vm_gap_shift -= @clz(vm_gap_size);
            std.debug.assert(vm_gap_size == @as(u64, 1) << @intCast(vm_gap_shift));
        }
        return .{
            .host_memory = @unionInit(HostMemory, @tagName(state), slice),
            .vm_addr_start = vm_addr,
            .vm_addr_end = vm_addr +| (slice.len * @as(u64, if (is_gapped) 2 else 1)),
            .vm_gap_shift = @intCast(vm_gap_shift),
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

    pub fn constSlice(self: Region) []const u8 {
        switch (self.host_memory) {
            .constant => |constant| return constant,
            .mutable => |mutable| return mutable,
        }
    }

    fn translate(
        self: Region,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
    ) ?state.Slice() {
        if (vm_addr < self.vm_addr_start) return null;

        const host_slice = self.hostSlice(state) orelse return null;
        const begin_offset = vm_addr - self.vm_addr_start;

        const is_in_gap = @as(u1, @truncate(begin_offset >> self.vm_gap_shift)) != 0;
        const gap_mask: u64 = ~@as(u64, 0) << self.vm_gap_shift;
        const gapped_offset = ((begin_offset & gap_mask) >> 1) | (begin_offset & ~gap_mask);
        const end_offset = gapped_offset +| len;

        if (end_offset <= host_slice.len and !is_in_gap) return host_slice[gapped_offset..][0..len];

        return null;
    }

    fn lessThanFn(context: void, lhs: Region, rhs: Region) bool {
        _ = context;
        return lhs.vm_addr_start < rhs.vm_addr_start;
    }

    fn regionsOverlap(sorted_regions: []const Region) bool {
        if (sorted_regions.len < 2) return false;
        var iter = std.mem.window(Region, sorted_regions, 2, 1);

        while (iter.next()) |region_pair| {
            if (region_pair[0].vm_addr_end > region_pair[1].vm_addr_start) return true;
        }
        return false;
    }

    fn isValidAccess(self: Region, access_type: MemoryState, vm_addr: u64) bool {
        if (access_type == .mutable and self.host_memory == .constant) return false;
        if (vm_addr >= self.vm_addr_end) return false;
        if (vm_addr < self.vm_addr_start) return false;

        return true;
    }
};

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L551
pub const AlignedMemoryMap = struct {
    regions: []Region,
    version: sbpf.Version,
    config: exe.Config,

    fn init(
        allocator: std.mem.Allocator,
        regions: []const Region,
        version: sbpf.Version,
        config: exe.Config,
    ) (error{OutOfMemory} || InitError)!AlignedMemoryMap {
        for (regions, 1..) |reg, index| {
            if (reg.vm_addr_start >> VIRTUAL_ADDRESS_BITS != index) {
                return error.InvalidMemoryRegion;
            }
        }
        return .{
            .regions = try allocator.dupe(Region, regions),
            .version = version,
            .config = config,
        };
    }

    fn deinit(self: *const AlignedMemoryMap, allocator: std.mem.Allocator) void {
        allocator.free(self.regions);
    }

    fn findRegion(self: *const AlignedMemoryMap, vm_addr: u64) !*Region {
        const err = accessViolation(vm_addr, self.version, self.config);

        const index = vm_addr >> VIRTUAL_ADDRESS_BITS;
        if (index == 0 or index > self.regions.len) return err;
        const reg = &self.regions[index - 1];
        if (vm_addr >= reg.vm_addr_start and vm_addr < reg.vm_addr_end) {
            return reg;
        }
        return err;
    }

    fn store(
        self: *const AlignedMemoryMap,
        comptime T: type,
        vm_addr: u64,
        value: T,
    ) !void {
        comptime std.debug.assert(@sizeOf(T) <= @sizeOf(u64));
        const slice = try self.vmap(.mutable, vm_addr, @sizeOf(T));
        std.mem.writeInt(T, slice[0..@sizeOf(T)], value, .little);
    }

    fn load(
        self: *const AlignedMemoryMap,
        comptime T: type,
        vm_addr: u64,
    ) !T {
        const slice = try self.vmap(.constant, vm_addr, @sizeOf(T));
        return std.mem.readInt(T, slice[0..@sizeOf(T)], .little);
    }

    // [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L628
    fn vmap(
        self: *const AlignedMemoryMap,
        comptime state: MemoryState,
        vm_addr: u64,
        len: u64,
    ) AccessError!state.Slice() {
        const reg = try self.findRegion(vm_addr);
        return self.mapRegion(state, reg.*, vm_addr, len);
    }

    fn mapRegion(
        self: *const AlignedMemoryMap,
        comptime state: MemoryState,
        reg: Region,
        vm_addr: u64,
        len: u64,
    ) AccessError!state.Slice() {
        return reg.translate(state, vm_addr, len) orelse
            return accessViolation(vm_addr, self.version, self.config);
    }
};

// [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/memory_region.rs#L187
fn accessViolation(
    vm_addr: u64,
    version: sbpf.Version,
    config: exe.Config,
) AccessError {
    const stack_frame_idx = std.math.divTrunc(
        i64,
        @as(i64, @bitCast(vm_addr)) -| @as(i64, STACK_START),
        @intCast(config.stack_frame_size),
    ) catch 0;

    return if (!version.enableDynamicStackFrames() and
        stack_frame_idx >= -1 and stack_frame_idx <= config.max_call_depth)
        error.StackAccessViolation
    else
        error.AccessViolation;
}

// [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L183
/// Memory mapping based on eytzinger search.
const UnalignedMemoryMap = struct {
    regions: []Region,
    region_addresses: []u64,
    version: sbpf.Version,
    config: exe.Config,

    // CoW callback
    //cow_cb: ?MemoryCowCallback,
    // Cache of the last `MappingCache::SIZE` vm_addr => region_index lookups
    //cache: MappingCache,

    // [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L241
    fn init(
        allocator: std.mem.Allocator,
        regions: []const Region,
        version: sbpf.Version,
        config: exe.Config,
    ) (error{OutOfMemory} || InitError)!UnalignedMemoryMap {
        // temporary allocation to keep regions a const slice
        const sorted_regions = try allocator.dupe(Region, regions);
        defer allocator.free(sorted_regions);
        std.mem.sort(Region, sorted_regions, {}, Region.lessThanFn);

        if (Region.regionsOverlap(sorted_regions)) return error.InvalidMemoryRegion;

        const region_addresses = try allocator.alloc(u64, sorted_regions.len);
        errdefer allocator.free(region_addresses);

        const etyzinger_regions = try allocator.alloc(Region, regions.len);
        errdefer allocator.free(etyzinger_regions);
        @memset(etyzinger_regions, .{
            .vm_addr_start = 0,
            .vm_addr_end = 0,
            .vm_gap_shift = 0,
            .host_memory = .{ .constant = "" },
        });

        var self: UnalignedMemoryMap = .{
            .regions = etyzinger_regions,
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
        in_index: usize,
        out_index: usize,
    ) usize {
        if (out_index >= ascending_regions.len) return in_index;

        const new_in_index = self.constructEytzingerOrder(
            ascending_regions,
            in_index,
            (out_index *| 2) +| 1,
        );

        {
            self.regions[out_index] = ascending_regions[new_in_index];
            // agave mutates ascending_regions like this, but there's no reason for it (mem::take).
            // ascending_regions[in_index] = Region.DEFAULT; // agave
        }

        self.region_addresses[out_index] = self.regions[out_index].vm_addr_start;

        return self.constructEytzingerOrder(
            ascending_regions,
            new_in_index +| 1,
            (out_index *| 2) +| 2,
        );
    }

    // [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L293
    // NOTE: agave-like cache unimplemented. Does not seem necessary.
    fn findRegion(self: *const UnalignedMemoryMap, vm_addr: u64) !*Region {
        var index: usize = 1;
        while (index <= self.region_addresses.len) {
            std.debug.assert(index > 0); // safe: index started at 1 and only increases.
            index = (index << 1) + @intFromBool(self.region_addresses[index - 1] <= vm_addr);
        }

        index = std.math.shr(usize, index, @ctz(index) + 1);
        return if (index == 0)
            accessViolation(vm_addr, self.version, self.config)
        else
            &self.regions[index - 1];
    }

    fn store(
        self: *const UnalignedMemoryMap,
        comptime T: type,
        vm_addr: u64,
        value: T,
    ) !void {
        const err = accessViolation(vm_addr, self.version, self.config);

        var region = try self.findRegion(vm_addr);
        if (region.host_memory != .mutable) return err;

        if (region.translate(.mutable, vm_addr, @sizeOf(T))) |slice| {
            // fast path
            std.mem.writeInt(T, slice[0..@sizeOf(T)], value, .little);
            return;
        }

        var current_addr = vm_addr;
        var src: []const u8 = std.mem.asBytes(&value);
        while (src.len > 0) {
            if (region.host_memory != .mutable) break;

            const write_len = @min(region.vm_addr_end -| current_addr, src.len);
            if (write_len == 0) break;

            if (region.translate(.mutable, current_addr, write_len)) |slice| {
                @memcpy(slice, src[0..write_len]);
                src = src[write_len..];
                if (src.len == 0) return; // done!
                current_addr = current_addr +| write_len;
                region = self.findRegion(current_addr) catch break;
            } else break;
        }

        return err;
    }

    fn load(
        self: *const UnalignedMemoryMap,
        comptime T: type,
        vm_addr: u64,
    ) !T {
        comptime std.debug.assert(@sizeOf(T) <= @sizeOf(u64));
        const err = accessViolation(vm_addr, self.version, self.config);

        var region = try self.findRegion(vm_addr);
        if (region.translate(.constant, vm_addr, @sizeOf(T))) |slice| {
            // fast path
            return std.mem.readInt(T, slice[0..@sizeOf(T)], .little);
        }

        var dest: [@sizeOf(T)]u8 = undefined;
        var ptr: []u8 = &dest;
        var current_addr = vm_addr;

        while (ptr.len > 0) {
            const load_len = @min(ptr.len, region.vm_addr_end -| current_addr);
            if (load_len == 0) break;
            if (region.translate(.constant, current_addr, load_len)) |slice| {
                @memcpy(ptr[0..load_len], slice);
                ptr = ptr[load_len..];
                if (ptr.len == 0) return @bitCast(dest);
                current_addr = current_addr +| load_len;
                region = self.findRegion(current_addr) catch break;
            } else break;
        }

        return err;
    }

    // [agave] https://github.com/anza-xyz/sbpf/blob/a8247dd30714ef286d26179771724b91b199151b/src/memory_region.rs#L323
    fn vmap(
        self: *const UnalignedMemoryMap,
        comptime access_type: MemoryState,
        vm_addr: u64,
        len: u64,
    ) AccessError!access_type.Slice() {
        const reg = try self.findRegion(vm_addr);
        return self.mapRegion(access_type, reg.*, vm_addr, len);
    }

    fn mapRegion(
        self: *const UnalignedMemoryMap,
        comptime state: MemoryState,
        reg: Region,
        vm_addr: u64,
        len: u64,
    ) AccessError!state.Slice() {
        return reg.translate(state, vm_addr, len) orelse
            return accessViolation(vm_addr, self.version, self.config);
    }
};

/// Returns true if T is a type that has a stable layout to be translated from VM memory.
fn hasTranslatableRepresentation(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .bool => false, // u8's should be used instead to be explicit on data layout.
        .int => |info| @sizeOf(T) * 8 == info.bits, // TODO: check for large than __uint128_t?
        .float => T == f32 or T == f64, // extern structs realistically only support float & double.
        .pointer => |info| info.size != .slice, // Slice have undefined memory layout.
        .array => |info| hasTranslatableRepresentation(info.child),
        .@"struct" => |info| switch (info.layout) {
            .auto => false, // Zig could change the size of structs any time.
            .@"packed" => hasTranslatableRepresentation(info.backing_integer orelse return false),
            .@"extern" => true, // any extern struct has a defined layout according to C.
        },
        else => false,
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/mod.rs#L235-L247
/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L609-L623
pub const VmSlice = extern struct {
    ptr: u64,
    len: u64,
};

const expectError = std.testing.expectError;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

test "hasTranslatableRepresentation" {
    try expectEqual(true, hasTranslatableRepresentation(u8));
    try expectEqual(true, hasTranslatableRepresentation(u16));
    try expectEqual(true, hasTranslatableRepresentation(i32));
    try expectEqual(true, hasTranslatableRepresentation(i64));
    try expectEqual(false, hasTranslatableRepresentation(u42));

    try expectEqual(true, hasTranslatableRepresentation(f32));
    try expectEqual(true, hasTranslatableRepresentation(f64));
    try expectEqual(false, hasTranslatableRepresentation(f128));
    try expectEqual(false, hasTranslatableRepresentation(f16));

    try expectEqual(true, hasTranslatableRepresentation(extern struct { x: u8 }));
    try expectEqual(true, hasTranslatableRepresentation(extern struct { x: u64, y: u8 }));
    try expectEqual(false, hasTranslatableRepresentation(packed struct { x: u64, y: u8 }));
    try expectEqual(true, hasTranslatableRepresentation(packed struct { x: u56, y: u8 }));

    try expectEqual(true, hasTranslatableRepresentation([3]u8));
    try expectEqual(false, hasTranslatableRepresentation([]u8));
    try expectEqual(true, hasTranslatableRepresentation([89]extern struct { x: f32 }));
    try expectEqual(false, hasTranslatableRepresentation([89]packed struct { x: u31 }));
}

test "aligned vmap" {
    var program_mem: [4]u8 = @splat(0xFF);
    var stack_mem: [4]u8 = @splat(0xDD);

    const allocator = std.testing.allocator; // needed for regions dupe
    var m = try MemoryMap.init(
        allocator,
        &.{
            Region.init(.mutable, &program_mem, RODATA_START),
            Region.init(.constant, &stack_mem, STACK_START),
        },
        .v2,
        .{},
    );
    defer m.deinit(allocator);

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
    var program_mem: [4]u8 = @splat(0xFF);
    var stack_mem: [4]u8 = @splat(0xDD);

    const allocator = std.testing.allocator; // needed for regions dupe
    var m = try MemoryMap.init(
        allocator,
        &.{
            Region.init(.mutable, &program_mem, RODATA_START),
            Region.init(.constant, &stack_mem, STACK_START),
        },
        .v2,
        .{},
    );
    defer m.deinit(allocator);

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
    var program_mem: [4]u8 = @splat(0xFF);
    var stack_mem: [4]u8 = @splat(0xDD);

    try expectError(
        error.InvalidMemoryRegion,
        MemoryMap.init(
            std.testing.failing_allocator,
            &.{
                Region.init(.constant, &stack_mem, STACK_START),
                Region.init(.mutable, &program_mem, RODATA_START),
            },
            .v0,
            .{},
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
            .v2,
            config,
        ),
    );

    const map = try UnalignedMemoryMap.init(
        allocator,
        &.{
            Region.init(.constant, mem1, INPUT_START),
            Region.init(.constant, mem2, INPUT_START + mem1.len),
        },
        .v2,
        config,
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
        .v2,
        config,
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
        .v2,
        config,
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

test "empty unaligned memory map" {
    const allocator = std.testing.failing_allocator;
    var mmap = try MemoryMap.init(
        allocator,
        &.{},
        .v2,
        .{ .aligned_memory_mapping = false },
    );
    defer mmap.deinit(allocator);
}

test "gapped map" {
    const allocator = std.testing.allocator;
    inline for (.{ true, false }) |aligned| {
        var mem1: [8]u8 = .{0xFF} ** 8;
        var map = try MemoryMap.init(allocator, &.{
            Region.init(.constant, &(.{0} ** 8), RODATA_START),
            Region.initGapped(.mutable, &mem1, STACK_START, 2),
        }, .v2, .{ .aligned_memory_mapping = aligned });
        defer map.deinit(allocator);

        for (0..4) |frame| {
            const address = STACK_START + frame * 4;
            _ = try map.region(.constant, address);
            _ = try map.vmap(.constant, address, 2);
            try expectError(error.AccessViolation, map.vmap(.constant, address + 2, 2));
            try expectEqualSlices(u8, try map.vmap(.constant, address, 2), &.{ 0xFF, 0xFF });
            try expectError(error.AccessViolation, map.vmap(.constant, address + 2, 2));
        }
    }
}

test "unaligned memory map store" {
    const allocator = std.testing.allocator;

    var mem1: [2]u8 = .{ 0xFF, 0xFF };
    var mem2: [1]u8 = .{0xFF};
    var mem3: [3]u8 = .{ 0xFF, 0xFF, 0xFF };
    var mem4: [2]u8 = .{ 0xFF, 0xFF };

    const m = try MemoryMap.init(allocator, &.{
        Region.init(.mutable, &mem1, INPUT_START),
        Region.init(.mutable, &mem2, INPUT_START + mem1.len),
        Region.init(.mutable, &mem3, INPUT_START + (mem1.len + mem2.len)),
        Region.init(.mutable, &mem4, INPUT_START + (mem1.len + mem2.len + mem3.len)),
    }, .v2, .{ .aligned_memory_mapping = false });
    defer m.deinit(allocator);

    try m.store(u16, INPUT_START, 0x1122);
    try expectEqual(0x1122, try m.load(u16, INPUT_START));

    try m.store(u32, INPUT_START, 0x33445566);
    try expectEqual(0x33445566, try m.load(u32, INPUT_START));

    try m.store(u64, INPUT_START, 0x778899AABBCCDDEE);
    try expectEqual(0x778899AABBCCDDEE, try m.load(u64, INPUT_START));
}

test "unaligned memory map fast paths" {
    const allocator = std.testing.allocator;

    var mem1: [8]u8 = .{0xFF} ** 8;

    const m = try MemoryMap.init(allocator, &.{
        Region.init(.mutable, &mem1, INPUT_START),
    }, .v2, .{ .aligned_memory_mapping = false });
    defer m.deinit(allocator);

    try m.store(u64, INPUT_START, 0x1122334455667788);
    try expectEqual(0x1122334455667788, try m.load(u64, INPUT_START));

    try m.store(u32, INPUT_START, 0x22334455);
    try expectEqual(0x22334455, try m.load(u32, INPUT_START));

    try m.store(u16, INPUT_START, 0x3344);
    try expectEqual(0x3344, try m.load(u16, INPUT_START));

    try m.store(u8, INPUT_START, 0x55);
    try expectEqual(0x55, try m.load(u8, INPUT_START));
}

test "unaligned memory map slow paths" {
    const allocator = std.testing.allocator;

    var mem1: [7]u8 = .{0xFF} ** 7;
    var mem2: [1]u8 = .{0xFF};

    const m = try MemoryMap.init(allocator, &.{
        Region.init(.mutable, &mem1, INPUT_START),
        Region.init(.mutable, &mem2, INPUT_START + mem1.len),
    }, .v2, .{ .aligned_memory_mapping = false });
    defer m.deinit(allocator);

    try m.store(u64, INPUT_START, 0x1122334455667788);
    try expectEqual(0x1122334455667788, try m.load(u64, INPUT_START));

    try m.store(u32, INPUT_START, 0xAABBCCDD);
    try expectEqual(0xAABBCCDD, try m.load(u32, INPUT_START));

    try m.store(u16, INPUT_START, 0xEEFF);
    try expectEqual(0xEEFF, try m.load(u16, INPUT_START));
}
