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

/// SIMD-0460: callback executed when a memory access misses its region.
///
/// The handler may mutate `region` in place to extend its host buffer / length
/// and re-permit the access; if after the call `region.translate(...)` still
/// fails, an `AccessViolation` is generated. It may also be used as a hook to
/// record the failing access for later remapping to a specific
/// `InstructionError` (read past account length → `AccountDataTooSmall`,
/// write past account growth budget → `InvalidRealloc`, etc.).
///
/// `address_space_reserved_for_account` is the distance from this region's
/// start to the next region's start (i.e. how far the region is allowed to
/// grow).
///
/// [agave] https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/memory_region.rs#L30
pub const AccessViolationHandler = struct {
    ctx: *anyopaque,
    call: *const fn (
        ctx: *anyopaque,
        region: *Region,
        address_space_reserved_for_account: u64,
        access_type: MemoryState,
        vm_addr: u64,
        len: u64,
    ) void,
};

// [agave] https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/memory_region.rs#L45
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

    /// SIMD-0460: install the access-violation handler used for direct-mapping
    /// auto-extension of writable+owned account regions and for recording the
    /// failing access for post-execution `InstructionError` remapping.
    ///
    /// Only the unaligned map (used under SIMD-0460) consults the handler.
    /// Setting it on an aligned map is a no-op — pre-SIMD-0460 paths neither
    /// auto-extend nor need the remap (the serialization buffer pre-reserves
    /// `MAX_PERMITTED_DATA_INCREASE`, so writes within budget never miss).
    pub fn setAccessViolationHandler(self: *MemoryMap, handler: AccessViolationHandler) void {
        switch (self.*) {
            .aligned => {},
            .unaligned => |*unaligned| unaligned.access_violation_handler = handler,
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
    /// SIMD-0460: user-defined payload (instruction account index) passed to
    /// the access-violation handler when this region triggers a violation.
    /// Set by the serialization / CPI paths for account-data regions; null
    /// for non-account regions (bytecode, stack, heap, scratch).
    /// [agave] https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/memory_region.rs#L57
    access_violation_handler_payload: ?u16 = null,

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

    /// Returns a copy of this region with `access_violation_handler_payload`
    /// set. Used by the serialization / CPI paths to tag account-data regions
    /// with the instruction-account index that the access-violation handler
    /// uses to look up the account.
    pub fn withPayload(self: Region, payload: u16) Region {
        var copy = self;
        copy.access_violation_handler_payload = payload;
        return copy;
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
    /// SIMD-0460: optional access-violation handler. When set and a multi-byte
    /// translate fails on the fast path, the handler is invoked with a pointer
    /// to the failing region. The handler may grow the region (for writable
    /// account-data regions) and/or record the failing access for later error
    /// remapping. If the access still doesn't fit after the call, the normal
    /// access violation is generated.
    access_violation_handler: ?AccessViolationHandler = null,

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

    /// SIMD-0460: distance from this region's start to the next region's
    /// start (in virtual address space). Equivalent to Agave's "max_len"
    /// passed to the AccessViolationHandler — the upper bound on how far
    /// this region may grow.
    /// [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/memory_region.rs#L514-L518
    fn addressSpaceReservedFor(self: *const UnalignedMemoryMap, region: *const Region) u64 {
        var next: u64 = std.math.maxInt(u64);
        for (self.regions) |reg| {
            if (reg.vm_addr_start > region.vm_addr_start and reg.vm_addr_start < next) {
                next = reg.vm_addr_start;
            }
        }
        return next -| region.vm_addr_start;
    }

    /// SIMD-0460: invoke the access-violation handler (if any) for a region
    /// that just failed translation, then retry the translation. Returns the
    /// slice if the handler grew the region enough to satisfy the access,
    /// null otherwise.
    fn tryHandlerThenTranslate(
        self: *const UnalignedMemoryMap,
        comptime state: MemoryState,
        region: *Region,
        vm_addr: u64,
        len: u64,
    ) ?state.Slice() {
        const handler = self.access_violation_handler orelse return null;
        const max_len = self.addressSpaceReservedFor(region);
        handler.call(handler.ctx, region, max_len, state, vm_addr, len);
        return region.translate(state, vm_addr, len);
    }

    fn store(
        self: *const UnalignedMemoryMap,
        comptime T: type,
        vm_addr: u64,
        value: T,
    ) !void {
        const err = accessViolation(vm_addr, self.version, self.config);

        var region = try self.findRegion(vm_addr);

        if (region.translate(.mutable, vm_addr, @sizeOf(T))) |slice| {
            // fast path
            std.mem.writeInt(T, slice[0..@sizeOf(T)], value, .little);
            return;
        }

        // SIMD-0460: invoke the access-violation handler (if installed) to
        // potentially grow the region. If it succeeds, the (re)translated
        // slice is valid; otherwise fall through to the pre-SIMD-0460
        // byte-level cross-region fallback (when not stricter) or to the
        // access violation (when stricter).
        if (self.tryHandlerThenTranslate(.mutable, region, vm_addr, @sizeOf(T))) |slice| {
            std.mem.writeInt(T, slice[0..@sizeOf(T)], value, .little);
            return;
        }

        // SIMD-0460: cross-region splits are access violations. The byte-level
        // fallback below is pre-SIMD-0460 behavior.
        if (self.config.virtual_address_space_adjustments) return err;

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

        // SIMD-0460: see note in store() above.
        if (self.tryHandlerThenTranslate(.constant, region, vm_addr, @sizeOf(T))) |slice| {
            return std.mem.readInt(T, slice[0..@sizeOf(T)], .little);
        }

        // SIMD-0460: cross-region splits are access violations. The byte-level
        // fallback below is pre-SIMD-0460 behavior.
        if (self.config.virtual_address_space_adjustments) return err;

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
        if (reg.translate(state, vm_addr, len)) |slice| return slice;
        // SIMD-0460: try the access-violation handler. We pass the original
        // region pointer (not the local copy) so the handler can mutate the
        // map's region in place; the eytzinger index remains valid because
        // the handler only grows `vm_addr_end` / refreshes `host_memory`
        // without changing `vm_addr_start`.
        if (self.access_violation_handler != null) {
            // Re-find by start address to get a stable pointer into self.regions.
            if (self.findRegion(reg.vm_addr_start)) |region_ptr| {
                if (self.tryHandlerThenTranslate(state, region_ptr, vm_addr, len)) |slice| {
                    return slice;
                }
            } else |_| {}
        }
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

// SIMD-0460 tests below cover the access-violation handler plumbing introduced
// for direct-mapping auto-extension of writable+owned account regions.

test "Region withPayload" {
    var buf: [4]u8 = .{ 1, 2, 3, 4 };
    const region = Region.init(.mutable, &buf, INPUT_START);
    try expectEqual(@as(?u16, null), region.access_violation_handler_payload);

    const tagged = region.withPayload(7);
    try expectEqual(@as(?u16, 7), tagged.access_violation_handler_payload);

    // `withPayload` returns a copy — the original must be untouched.
    try expectEqual(@as(?u16, null), region.access_violation_handler_payload);
    // Address/size fields are preserved.
    try expectEqual(region.vm_addr_start, tagged.vm_addr_start);
    try expectEqual(region.vm_addr_end, tagged.vm_addr_end);
    try expectEqual(region.vm_gap_shift, tagged.vm_gap_shift);
}

test "setAccessViolationHandler is a no-op on aligned memory maps" {
    const allocator = std.testing.allocator;
    var buf: [4]u8 = .{0xFF} ** 4;

    // The aligned map enforces that region N starts at (N << VIRTUAL_ADDRESS_BITS),
    // so a single-region map must place the region at RODATA_START.
    var map = try MemoryMap.init(
        allocator,
        &.{Region.init(.mutable, &buf, RODATA_START)},
        .v2,
        .{ .aligned_memory_mapping = true },
    );
    defer map.deinit(allocator);

    const Handler = struct {
        var called: bool = false;
        fn handle(
            _: *anyopaque,
            _: *Region,
            _: u64,
            _: MemoryState,
            _: u64,
            _: u64,
        ) void {
            called = true;
        }
    };
    Handler.called = false;
    var dummy_ctx: u8 = 0;
    map.setAccessViolationHandler(.{ .ctx = @ptrCast(&dummy_ctx), .call = Handler.handle });

    // An access that misses the region must not invoke the handler under
    // the aligned map — pre-SIMD-0460 code paths never consult it.
    _ = map.load(u32, RODATA_START + 100) catch {};
    _ = map.store(u32, RODATA_START + 100, 0) catch {};
    try std.testing.expect(!Handler.called);
}

// Exercises the full handler path on store():
//   1. fast-path hit (handler not called)
//   2. fast-path miss → handler grows the region → retry succeeds
//   3. fast-path miss → handler doesn't grow → AccessViolation
// Also verifies that handler.max_len equals the address-space-reserved-for
// computation: distance to the next region's start (or maxInt - start for the
// last region).
test "AccessViolationHandler grows region on store miss" {
    const allocator = std.testing.allocator;

    // Two adjacent regions with a gap (next region starts at INPUT_START + 64).
    const gap: u64 = 64;
    var ext_buf: [16]u8 = @splat(0);
    var mem1: [4]u8 = .{0xFF} ** 4;
    var mem2: [4]u8 = .{0xEE} ** 4;

    var map = try MemoryMap.init(
        allocator,
        &.{
            Region.init(.mutable, &mem1, INPUT_START),
            Region.init(.mutable, &mem2, INPUT_START + gap),
        },
        .v2,
        .{ .aligned_memory_mapping = false, .virtual_address_space_adjustments = true },
    );
    defer map.deinit(allocator);

    const Handler = struct {
        var call_count: usize = 0;
        var last_max_len: u64 = 0;
        var last_vm_addr: u64 = 0;
        var last_access_type: MemoryState = .constant;
        var grow: bool = true;
        var ext_ptr: ?*[16]u8 = null;

        fn handle(
            _: *anyopaque,
            region: *Region,
            max_len: u64,
            access_type: MemoryState,
            vm_addr: u64,
            _: u64,
        ) void {
            call_count += 1;
            last_max_len = max_len;
            last_vm_addr = vm_addr;
            last_access_type = access_type;

            if (!grow) return;
            // Re-point the region at our larger backing buffer and grow its
            // vm_addr_end to cover it. The replacement slice must start at the
            // same vm_addr_start (and remain mutable for mutable accesses).
            const ext = ext_ptr.?;
            region.host_memory = .{ .mutable = ext };
            region.vm_addr_end = region.vm_addr_start +| ext.len;
        }
    };
    Handler.call_count = 0;
    Handler.ext_ptr = &ext_buf;
    Handler.grow = true;
    var dummy_ctx: u8 = 0;
    map.setAccessViolationHandler(.{ .ctx = @ptrCast(&dummy_ctx), .call = Handler.handle });

    // Fast-path hit: write fully inside mem1 → handler must not be called.
    try map.store(u32, INPUT_START, 0x11223344);
    try expectEqual(@as(usize, 0), Handler.call_count);
    try expectEqual(@as(u32, 0x11223344), std.mem.readInt(u32, &mem1, .little));

    // Miss: write past mem1's end but inside its reserved range → handler
    // grows the region → retry succeeds.
    try map.store(u32, INPUT_START + 8, 0xAABBCCDD);
    try expectEqual(@as(usize, 1), Handler.call_count);
    try expectEqual(MemoryState.mutable, Handler.last_access_type);
    try expectEqual(@as(u64, INPUT_START + 8), Handler.last_vm_addr);
    // max_len = next region start (INPUT_START + gap) - INPUT_START = gap.
    try expectEqual(gap, Handler.last_max_len);
    try expectEqual(@as(u32, 0xAABBCCDD), std.mem.readInt(u32, ext_buf[8..12], .little));

    // Handler declines to grow → AccessViolation. Reset region so the test
    // is independent of the previous one's growth.
    var map2 = try MemoryMap.init(
        allocator,
        &.{Region.init(.mutable, &mem1, INPUT_START)},
        .v2,
        .{ .aligned_memory_mapping = false, .virtual_address_space_adjustments = true },
    );
    defer map2.deinit(allocator);
    Handler.call_count = 0;
    Handler.grow = false;
    map2.setAccessViolationHandler(
        .{ .ctx = @ptrCast(&dummy_ctx), .call = Handler.handle },
    );
    try expectError(error.AccessViolation, map2.store(u32, INPUT_START + 8, 0));
    try expectEqual(@as(usize, 1), Handler.call_count);
    // Last region in the map → max_len reaches to maxInt(u64) from region start.
    try expectEqual(std.math.maxInt(u64) - INPUT_START, Handler.last_max_len);
}

test "AccessViolationHandler grows region on load miss" {
    const allocator = std.testing.allocator;

    var ext_buf: [16]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var mem1: [4]u8 = .{ 0xAA, 0xBB, 0xCC, 0xDD };

    var map = try MemoryMap.init(
        allocator,
        &.{Region.init(.mutable, &mem1, INPUT_START)},
        .v2,
        .{ .aligned_memory_mapping = false, .virtual_address_space_adjustments = true },
    );
    defer map.deinit(allocator);

    const Handler = struct {
        var call_count: usize = 0;
        var last_access_type: MemoryState = .mutable;
        var ext_ptr: ?*[16]u8 = null;

        fn handle(
            _: *anyopaque,
            region: *Region,
            _: u64,
            access_type: MemoryState,
            _: u64,
            _: u64,
        ) void {
            call_count += 1;
            last_access_type = access_type;
            const ext = ext_ptr.?;
            region.host_memory = .{ .mutable = ext };
            region.vm_addr_end = region.vm_addr_start +| ext.len;
        }
    };
    Handler.call_count = 0;
    Handler.ext_ptr = &ext_buf;
    var dummy_ctx: u8 = 0;
    map.setAccessViolationHandler(.{ .ctx = @ptrCast(&dummy_ctx), .call = Handler.handle });

    // Fast-path read: no handler call.
    try expectEqual(@as(u32, 0xDDCCBBAA), try map.load(u32, INPUT_START));
    try expectEqual(@as(usize, 0), Handler.call_count);

    // Miss: read past mem1's end → handler grows → retry succeeds.
    // Handler is invoked with `.constant` for reads (this is the signal used
    // by `remapAccessViolation` to distinguish AccountDataTooSmall from
    // InvalidRealloc — see runtime/program/bpf_loader/execute.zig).
    const read = try map.load(u32, INPUT_START + 8);
    try expectEqual(@as(usize, 1), Handler.call_count);
    try expectEqual(MemoryState.constant, Handler.last_access_type);
    try expectEqual(std.mem.readInt(u32, ext_buf[8..12], .little), read);
}

// Without the handler, virtual_address_space_adjustments=true forbids the
// pre-SIMD-0460 byte-level cross-region fallback that store/load otherwise use.
// This locks in the SIMD-0460 rule: multi-byte accesses must be wholly within
// a single region.
test "virtual_address_space_adjustments disables cross-region byte fallback" {
    const allocator = std.testing.allocator;

    {
        var mem1: [3]u8 = .{0xFF} ** 3;
        var mem2: [5]u8 = .{0xFF} ** 5;

        const map = try MemoryMap.init(
            allocator,
            &.{
                Region.init(.mutable, &mem1, INPUT_START),
                Region.init(.mutable, &mem2, INPUT_START + 3),
            },
            .v2,
            .{ .aligned_memory_mapping = false, .virtual_address_space_adjustments = true },
        );
        defer map.deinit(allocator);

        // u32 at INPUT_START spans mem1 (3B) + mem2 (1B) → cross-region.
        // With virtual_address_space_adjustments=true and no handler, this is
        // an AccessViolation; the byte-level fallback path must be skipped.
        try expectError(error.AccessViolation, map.store(u32, INPUT_START, 0x11223344));
        try expectError(error.AccessViolation, map.load(u32, INPUT_START));
    }

    // Mirror of the existing slow-path test: with virtual_address_space_adjustments=false,
    // the same cross-region access succeeds via the byte-level fallback.
    {
        var mem1: [3]u8 = .{0xFF} ** 3;
        var mem2: [5]u8 = .{0xFF} ** 5;

        const map = try MemoryMap.init(
            allocator,
            &.{
                Region.init(.mutable, &mem1, INPUT_START),
                Region.init(.mutable, &mem2, INPUT_START + 3),
            },
            .v2,
            .{ .aligned_memory_mapping = false, .virtual_address_space_adjustments = false },
        );
        defer map.deinit(allocator);

        try map.store(u32, INPUT_START, 0x11223344);
        try expectEqual(@as(u32, 0x11223344), try map.load(u32, INPUT_START));
    }
}

// vmap() / mapRegion() goes through the handler too: a translation that misses
// the bounds gets one retry after the handler runs.
test "AccessViolationHandler grows region on vmap miss" {
    const allocator = std.testing.allocator;

    var ext_buf: [32]u8 = @splat(0);
    var mem1: [4]u8 = .{0xFF} ** 4;

    var map = try MemoryMap.init(
        allocator,
        &.{Region.init(.mutable, &mem1, INPUT_START)},
        .v2,
        .{ .aligned_memory_mapping = false, .virtual_address_space_adjustments = true },
    );
    defer map.deinit(allocator);

    const Handler = struct {
        var call_count: usize = 0;
        var ext_ptr: ?*[32]u8 = null;
        fn handle(
            _: *anyopaque,
            region: *Region,
            _: u64,
            _: MemoryState,
            _: u64,
            _: u64,
        ) void {
            call_count += 1;
            const ext = ext_ptr.?;
            region.host_memory = .{ .mutable = ext };
            region.vm_addr_end = region.vm_addr_start +| ext.len;
        }
    };
    Handler.call_count = 0;
    Handler.ext_ptr = &ext_buf;
    var dummy_ctx: u8 = 0;
    map.setAccessViolationHandler(.{ .ctx = @ptrCast(&dummy_ctx), .call = Handler.handle });

    // vmap covering bytes that extend past the original region must succeed
    // after the handler grows it.
    const slice = try map.vmap(.mutable, INPUT_START + 4, 8);
    try expectEqual(@as(usize, 1), Handler.call_count);
    try expectEqual(@as(usize, 8), slice.len);
    try expectEqual(ext_buf[4..12].ptr, slice.ptr);
}

// vmap() must still report AccessViolation when no handler is installed (or
// the handler declines to grow), guarding against a regression where the
// handler integration accidentally suppresses errors.
test "vmap returns AccessViolation when handler declines to grow" {
    const allocator = std.testing.allocator;
    var mem1: [4]u8 = .{0xFF} ** 4;

    var map = try MemoryMap.init(
        allocator,
        &.{Region.init(.mutable, &mem1, INPUT_START)},
        .v2,
        .{ .aligned_memory_mapping = false, .virtual_address_space_adjustments = true },
    );
    defer map.deinit(allocator);

    // No handler installed → access past region is an AccessViolation.
    try expectError(error.AccessViolation, map.vmap(.mutable, INPUT_START + 4, 4));

    const Noop = struct {
        var called: bool = false;
        fn handle(
            _: *anyopaque,
            _: *Region,
            _: u64,
            _: MemoryState,
            _: u64,
            _: u64,
        ) void {
            called = true;
        }
    };
    Noop.called = false;
    var dummy_ctx: u8 = 0;
    map.setAccessViolationHandler(.{ .ctx = @ptrCast(&dummy_ctx), .call = Noop.handle });

    // Handler runs but doesn't grow → still AccessViolation, but the handler
    // was given a chance (important: this is where the bpf_loader records
    // `last_access_violation` for error remapping).
    try expectError(error.AccessViolation, map.vmap(.mutable, INPUT_START + 4, 4));
    try std.testing.expect(Noop.called);
}
