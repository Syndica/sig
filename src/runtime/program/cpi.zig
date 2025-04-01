const std = @import("std");
const sig = @import("../../sig.zig");

const memory = @import("../../vm/memory.zig");
const MemoryMap = memory.MemoryMap;

const ids = sig.runtime.ids;
const bincode = sig.bincode;
const sysvar = sig.runtime.sysvar;
const bpf_loader_program = sig.runtime.program.bpf_loader_program;
const system_program = sig.runtime.program.system_program;
const feature_set = sig.runtime.feature_set;

const Pubkey = sig.core.Pubkey;
const ComputeBudget = sig.runtime.ComputeBudget;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;
const TransactionContextAccount = sig.runtime.TransactionContextAccount;
const AccountSharedData = sig.runtime.AccountSharedData;
const LogCollector = sig.runtime.LogCollector;

const Epoch = sig.core.Epoch;

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L86
const SyscallError = error{
    InvalidPointer,
    InvalidLength,
    UnalignedPointer,
};

fn StableVec(comptime T: type) type {
    return extern struct {
        const Self = @This();

        addr: u64,
        cap: u64,
        len: u64,

        fn slice(self: Self, comptime state: memory.MemoryState) switch (state) {
            .constant => []const T,
            .mutable => []T,
        } {
            return switch (state) {
                .constant => @as([*]const T, @ptrFromInt(self.addr))[0..self.len],
                .mtuable => @as([*]T, @ptrFromInt(self.addr))[0..self.len],
            };
        }
    };
}

const StableInstruction = extern struct {
    accounts: StableVec(AccountMeta),
    data: StableVec(u8),
    program_id: Pubkey,
};

/// This struct will be backed by mmaped and snapshotted data files.
/// So the data layout must be stable and consistent across the entire cluster!
const AccountMeta = extern struct {
    /// lamports in the account
    lamports: u64,
    /// the epoch at which this account will next owe rent
    rent_epoch: Epoch,
    /// the program that owns this account. If executable, the program that loads this account.
    owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    executable: bool,
};

const SerializedAccountMetadata = struct {
    original_data_len: usize,
    vm_data_addr: u64,
    vm_key_addr: u64,
    vm_lamports_addr: u64,
    vm_owner_addr: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/master/359d7eb2b68639443d750ffcec0c7e358f138975/bpf_loader/src/syscalls/cpi.rs#L597
const SolAccountInfo = extern struct {
    key_addr: u64,
    lamports_addr: u64,
    data_len: u64,
    data_addr: u64,
    owner_addr: u64,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
};

/// [rust] https://doc.rust-lang.org/src/alloc/rc.rs.html#281-289
/// [agave] https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/cpi.rs#L2971
fn RcBox(comptime T: type) type {
    return extern struct {
        strong: usize = 0,
        weak: usize = 0,
        value: T,

        const VALUE_OFFSET = @sizeOf(usize) * 2;

        fn asPtr(self: *@This()) *T {
            return &self.value;
        }
    };
}

/// [rust] https://doc.rust-lang.org/src/alloc/rc.rs.html#314-317
fn Rc(comptime T: type) type {
    return extern struct {
        ptr: *RcBox(T),

        fn fromRaw(value_ptr: *T) @This() {
            return .{ .ptr = @fieldParentPtr("value", value_ptr) };
        }
    };
}

/// [rust] https://doc.rust-lang.org/src/core/cell.rs.html#730
fn RefCell(comptime T: type) type {
    return extern struct {
        borrow: isize = 0,
        value: [@sizeOf(T)]u8 align(@alignOf(T)), // support defined-layout when T isnt.

        pub fn init(value: T) @This() {
            return .{ .value = std.mem.asBytes(&value)[0..@sizeOf(T)].* };
        }
    };
}

/// [???] https://docs.rs/anchor-lang/latest/anchor_lang/prelude/struct.AccountInfo.html
const AccountInfo = extern struct {
    key: *const Pubkey,
    lamports: Rc(RefCell(*u64)),
    data: Rc(RefCell([]u8)),
    owner: *const Pubkey,
    rent_epoch: Epoch,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
};

fn VmValue(comptime T: type) type {
    return union(enum) {
        const Self = @This();

        vm_address: struct {
            vm_addr: u64,
            memory_map: *const MemoryMap,
            check_aligned: bool,
        },
        translated: *T,

        pub fn get(self: Self, comptime state: memory.MemoryState) !(switch (state) {
            .constant => *const T,
            .mutable => *T,
        }) {
            switch (self) {
                .translated => |ptr| return ptr,
                .vm_address => |vma| {
                    return translateType(T, state, vma.memory_map, vma.vm_addr, vma.check_aligned);
                },
            }
        }
    };
}

const MM_INPUT_START = memory.INPUT_START;

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L604
fn translate(
    memory_map: *const MemoryMap,
    comptime state: memory.MemoryState,
    vm_addr: u64,
    len: u64,
) !u64 {
    const slice = try memory_map.vmap(state, vm_addr, len);
    return @intFromPtr(slice.ptr);
}

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L616
fn translateType(
    comptime T: type,
    comptime state: memory.MemoryState,
    memory_map: *const MemoryMap,
    vm_addr: u64,
    check_aligned: bool,
) !(switch (state) {
    .mutable => *T,
    .constant => *const T,
}) {
    const host_addr = try translate(memory_map, state, vm_addr, @sizeOf(u64));
    if (!check_aligned) {
        return @ptrFromInt(host_addr);
    } else if (host_addr % @alignOf(T) != 0) {
        return SyscallError.UnalignedPointer;
    } else {
        return @ptrFromInt(host_addr);
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L647
fn translateSlice(
    comptime T: type,
    comptime state: memory.MemoryState,
    memory_map: *const MemoryMap,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) !switch (state) {
    .mutable => []T,
    .constant => []const T,
} {
    if (len == 0) {
        const Static = struct {
            var _: [0]T = undefined;
        };
        return &Static._;
    }

    const total_size = std.math.mul(u64, len, @sizeOf(u64)) catch std.math.maxInt(u64);
    _ = std.math.cast(isize, total_size) orelse return SyscallError.InvalidLength;

    const host_addr = try translate(memory_map, state, vm_addr, total_size);
    if (check_aligned and host_addr % @alignOf(T) != 0) {
        return SyscallError.UnalignedPointer;
    }

    return switch (state) {
        .mutable => @as([*]T, @ptrFromInt(host_addr))[0..len],
        .constant => @as([*]const T, @ptrFromInt(host_addr))[0..len],
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L38
fn checkAccountInfoPtr(
    ic: *InstructionContext,
    vm_addr: u64,
    expected_vm_addr: u64,
    field: []const u8,
) !void {
    if (vm_addr != expected_vm_addr) {
        try ic.tc.log("Invalid account info pointer `{s}`: {x} != {x}", .{
            field,
            vm_addr,
            expected_vm_addr,
        });
        return SyscallError.InvalidPointer;
    }
}

/// Host side representation of AccountInfo or SolAccountInfo passed to the CPI syscall.
///
/// At the start of a CPI, this can be different from the data stored in the
/// corresponding BorrowedAccount, and needs to be synched.
///
/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L96
const CallerAccount = struct {
    lamports: *u64,
    owner: *Pubkey,
    // The original data length of the account at the start of the current
    // instruction. We use this to determine wether an account was shrunk or
    // grown before or after CPI, and to derive the vm address of the realloc
    // region.
    original_data_len: usize,
    // This points to the data section for this account, as serialized and
    // mapped inside the vm (see serialize_parameters() in
    // BpfExecutor::execute).
    //
    // This is only set when direct mapping is off (see the relevant comment in
    // CallerAccount::from_account_info).
    serialized_data: []u8,
    // Given the corresponding input AccountInfo::data, vm_data_addr points to
    // the pointer field and ref_to_len_in_vm points to the length field.
    vm_data_addr: u64,
    ref_to_len_in_vm: VmValue(u64),

    /// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L119
    fn fromAccountInfo(
        ic: *InstructionContext,
        memory_map: *const MemoryMap,
        account_info: *const AccountInfo,
        account_metadata: *const SerializedAccountMetadata,
    ) !CallerAccount {
        const direct_mapping = ic.tc.feature_set.active.contains(
            feature_set.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
        );

        if (direct_mapping) {
            try checkAccountInfoPtr(
                ic,
                @intFromPtr(account_info.key),
                account_metadata.vm_key_addr,
                "key",
            );
            try checkAccountInfoPtr(
                ic,
                @intFromPtr(account_info.owner),
                account_metadata.vm_owner_addr,
                "owner",
            );
        }

        // account_info points to host memory. The addresses used internally are
        // in vm space so they need to be translated.
        const lamports: *u64 = blk: {
            // NOTE: trying to model the ptr stuff going on here:
            // [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L151
            const lamports_addr: u64 = @intFromPtr(account_info.lamports.ptr.asPtr());

            // Double translate lamports out of RefCell
            const ptr: *const u64 = try translateType(
                u64,
                .constant,
                memory_map,
                lamports_addr,
                ic.getCheckAligned(),
            );
            if (direct_mapping) {
                if (lamports_addr >= MM_INPUT_START) {
                    return SyscallError.InvalidPointer;
                }
                try checkAccountInfoPtr(
                    ic,
                    ptr.*,
                    account_metadata.vm_lamports_addr,
                    "lamports",
                );
            }
            break :blk try translateType(
                u64,
                .mutable,
                memory_map,
                ptr.*,
                ic.getCheckAligned(),
            );
        };

        const owner: *Pubkey = try translateType(
            Pubkey,
            .mutable,
            memory_map,
            @intFromPtr(account_info.owner),
            ic.getCheckAligned(),
        );

        const serialized, const vm_data_addr, const ref_to_len = blk: {
            // NOTE: trying to model the ptr stuff going on here:
            // [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L183
            const data_ptr: u64 = @intFromPtr(account_info.data.ptr.asPtr());

            if (direct_mapping and data_ptr >= MM_INPUT_START) {
                return SyscallError.InvalidPointer;
            }

            // Double translate data out of RefCell
            const data: []const u8 = (try translateType(
                []const u8,
                .constant,
                memory_map,
                data_ptr,
                ic.getCheckAligned(),
            )).*;

            if (direct_mapping) {
                try checkAccountInfoPtr(
                    ic,
                    data_ptr,
                    account_metadata.vm_data_addr,
                    "data",
                );
            }

            // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/bpf_loader/src/syscalls/cpi.rs#L195-L200
            try ic.tc.consumeCompute(std.math.divFloor(
                u64,
                data.len,
                ic.tc.compute_budget.cpi_bytes_per_unit,
            ) catch std.math.maxInt(u64));

            const ref_to_len = if (direct_mapping) r2l: {
                const vm_addr = data_ptr +| @sizeOf(u64);
                if (vm_addr >= MM_INPUT_START) {
                    return SyscallError.InvalidPointer;
                }
                // In the same vein as the other check_account_info_pointer() checks, we don't lock
                // this pointer to a specific address but we don't want it to be inside accounts, or
                // callees might be able to write to the pointed memory.
                break :r2l VmValue(u64){ .vm_address = .{
                    .vm_addr = vm_addr,
                    .memory_map = memory_map,
                    .check_aligned = ic.getCheckAligned(),
                } };
            } else r2l: {
                const translated: *u64 = @ptrFromInt(try translate(
                    memory_map,
                    .constant,
                    data_ptr +| @sizeOf(u64),
                    8,
                ));
                break :r2l VmValue(u64){ .translated = translated };
            };

            const vm_data_addr = @intFromPtr(data.ptr);
            const serialized = if (direct_mapping) ser: {
                // when direct mapping is enabled, the permissions on the
                // realloc region can change during CPI so we must delay
                // translating until when we know whether we're going to mutate
                // the realloc region or not. Consider this case:
                //
                // [caller can't write to an account] <- we are here
                // [callee grows and assigns account to the caller]
                // [caller can now write to the account]
                //
                // If we always translated the realloc area here, we'd get a
                // memory access violation since we can't write to the account
                // _yet_, but we will be able to once the caller returns.
                const Static = struct {
                    var _: [0]u8 = undefined;
                };
                break :ser &Static._;
            } else try translateSlice(
                u8,
                .mutable,
                memory_map,
                vm_data_addr,
                data.len,
                ic.getCheckAligned(),
            );

            break :blk .{ serialized, vm_data_addr, ref_to_len };
        };

        return .{
            .lamports = lamports,
            .owner = owner,
            .original_data_len = account_metadata.original_data_len,
            .serialized_data = serialized,
            .vm_data_addr = vm_data_addr,
            .ref_to_len_in_vm = ref_to_len,
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L264
    fn fromSolAccountInfo(
        ic: *InstructionContext,
        memory_map: *const MemoryMap,
        vm_addr: u64,
        account_info: *const SolAccountInfo,
        account_metadata: *const SerializedAccountMetadata,
    ) !CallerAccount {
        const direct_mapping = ic.tc.feature_set.active.contains(
            feature_set.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
        );

        if (direct_mapping) {
            try checkAccountInfoPtr(
                ic,
                account_info.key_addr,
                account_metadata.vm_key_addr,
                "key",
            );
            try checkAccountInfoPtr(
                ic,
                account_info.owner_addr,
                account_metadata.vm_owner_addr,
                "owner",
            );
            try checkAccountInfoPtr(
                ic,
                account_info.lamports_addr,
                account_metadata.vm_lamports_addr,
                "lamports",
            );
            try checkAccountInfoPtr(
                ic,
                account_info.data_addr,
                account_metadata.vm_data_addr,
                "data",
            );
        }

        // account_info points to host memory. The addresses used internally are
        // in vm space so they need to be translated.
        const lamports = try translateType(
            u64,
            .mutable,
            memory_map,
            account_info.lamports_addr,
            ic.getCheckAligned(),
        );
        const owner = try translateType(
            Pubkey,
            .mutable,
            memory_map,
            account_info.owner_addr,
            ic.getCheckAligned(),
        );

        try ic.tc.consumeCompute(std.math.divFloor(
            u64,
            account_info.data_len,
            ic.tc.compute_budget.cpi_bytes_per_unit,
        ) catch std.math.maxInt(u64));

        const serialized_data = if (direct_mapping) ser: {
            // See comment in CallerAccount::from_account_info()
            const Static = struct {
                var _: [0]u8 = undefined;
            };
            break :ser &Static._;
        } else try translateSlice(
            u8,
            .mutable,
            memory_map,
            account_info.data_addr,
            account_info.data_len,
            ic.getCheckAligned(),
        );

        // we already have the host addr we want: &mut account_info.data_len.
        // The account info might be read only in the vm though, so we translate
        // to ensure we can write. This is tested by programs/sbf/rust/ro_modify
        // which puts SolAccountInfo in rodata.
        const data_len_vm_addr = vm_addr +|
            @intFromPtr(&account_info.data_len) -|
            @intFromPtr(account_info);

        const ref_to_len = if (direct_mapping)
            VmValue(u64){ .vm_address = .{
                .vm_addr = data_len_vm_addr,
                .memory_map = memory_map,
                .check_aligned = ic.getCheckAligned(),
            } }
        else
            VmValue(u64){ .translated = @ptrFromInt(try translate(
                memory_map,
                .mutable,
                data_len_vm_addr,
                @sizeOf(u64),
            )) };

        return .{
            .lamports = lamports,
            .owner = owner,
            .original_data_len = account_metadata.original_data_len,
            .serialized_data = serialized_data,
            .vm_data_addr = account_info.data_addr,
            .ref_to_len_in_vm = ref_to_len,
        };
    }

    // [agave] https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/cpi.rs#L372C8-L372C22
    // fn reallocRegion(
    //     self: *const CallerAccount,
    //     allocator: std.mem.Allocator,
    //     memory_map: *const MemoryMap,
    //     is_loader_deprecated: bool,
    // ) !?*const memory.Region {
    //     return accountReallocRegion(
    //         memory_map,
    //         self.vm_data_addr,
    //         self.original_data_len,
    //         is_loader_deprecated,
    //     );
    // }
};

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L2770
const MockInstruction = struct {
    program_id: Pubkey,
    accounts: []const AccountMeta,
    data: []const u8,

    /// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L2777
    fn intoRegion(
        self: MockInstruction,
        allocator: std.mem.Allocator,
        vm_addr: u64,
    ) !struct { []u8, memory.Region } {
        const accounts_len = @sizeOf(AccountMeta) * self.accounts.len;
        const size = @sizeOf(StableInstruction) + accounts_len + self.data.len;

        const data = try allocator.alloc(u8, size);
        errdefer allocator.free(data);

        const ins = StableInstruction{
            .program_id = self.program_id,
            .accounts = StableVec(AccountMeta){
                .addr = vm_addr + @sizeOf(StableInstruction),
                .cap = self.accounts.len,
                .len = self.accounts.len,
            },
            .data = StableVec(u8){
                .addr = vm_addr + @sizeOf(StableInstruction) + accounts_len,
                .cap = self.data.len,
                .len = self.data.len,
            },
        };

        var buf = std.io.fixedBufferStream(data);
        try buf.writer().writeAll(std.mem.asBytes(&ins));
        try buf.writer().writeAll(std.mem.sliceAsBytes(self.accounts));
        try buf.writer().writeAll(self.data);

        return .{ data, memory.Region.init(.mutable, data, vm_addr) };
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L2870
const MockAccountInfo = struct {
    key: Pubkey,
    is_signer: bool,
    is_writable: bool,
    lamports: u64,
    data: []const u8,
    owner: Pubkey,
    executable: bool,
    rent_epoch: Epoch,

    /// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L2895
    fn intoRegion(
        self: MockAccountInfo,
        allocator: std.mem.Allocator,
        vm_addr: u64,
    ) !struct { []u8, memory.Region, SerializedAccountMetadata } {
        const size = @sizeOf(AccountInfo) +
            @sizeOf(Pubkey) * 2 +
            @sizeOf(RcBox(RefCell(*u64))) +
            @sizeOf(u64) +
            @sizeOf(RcBox(RefCell([]u8))) +
            self.data.len;

        const data = try allocator.alloc(u8, size);
        defer allocator.free(data);

        const key_addr = vm_addr + @sizeOf(AccountInfo);
        const lamports_cell_addr = key_addr + @sizeOf(Pubkey);
        const lamports_addr = lamports_cell_addr + @sizeOf(RcBox(RefCell(*u64)));
        const owner_addr = lamports_addr + @sizeOf(u64);
        const data_cell_addr = owner_addr + @sizeOf(Pubkey);
        const data_addr = data_cell_addr + @sizeOf(RcBox(RefCell([]u8)));

        const info = AccountInfo{
            .key = @ptrFromInt(key_addr),
            .is_signer = self.is_signer,
            .is_writable = self.is_writable,
            .lamports = Rc(RefCell(*u64)).fromRaw(
                @ptrFromInt(lamports_cell_addr + RcBox(*u64).VALUE_OFFSET),
            ),
            .data = Rc(RefCell([]u8)).fromRaw(
                @ptrFromInt(data_cell_addr + RcBox([]u8).VALUE_OFFSET),
            ),
            .owner = @ptrFromInt(owner_addr),
            .executable = self.executable,
            .rent_epoch = self.rent_epoch,
        };

        data[0..@sizeOf(AccountInfo)].* = @bitCast(info);
        data[key_addr - vm_addr ..][0..@sizeOf(Pubkey)].* = @bitCast(self.key);
        data[lamports_cell_addr - vm_addr ..][0..@sizeOf(RcBox(RefCell(*u64)))].* = @bitCast(
            RcBox(RefCell(*u64)){
                .value = RefCell(*u64).init(@ptrFromInt(lamports_addr)),
            },
        );
        data[lamports_addr - vm_addr ..][0..@sizeOf(u64)].* = @bitCast(self.lamports);
        data[owner_addr - vm_addr ..][0..@sizeOf(Pubkey)].* = @bitCast(self.owner);
        data[data_cell_addr - vm_addr ..][0..@sizeOf(RcBox(RefCell([]u8)))].* = @bitCast(
            RcBox(RefCell([]u8)){
                .value = RefCell([]u8).init(@as([*]u8, @ptrFromInt(data_addr))[0..self.data.len]),
            },
        );
        @memcpy(data[data_addr - vm_addr ..][0..self.data.len], self.data);

        return .{
            data,
            memory.Region.init(.mutable, data, vm_addr),
            .{
                .original_data_len = data.len,
                .vm_key_addr = key_addr,
                .vm_lamports_addr = lamports_addr,
                .vm_owner_addr = owner_addr,
                .vm_data_addr = data_addr,
            },
        };
    }
};

test "CallerAccount" {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const account_key = Pubkey.initRandom(prng.random());

    var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{
            .{
                .pubkey = account_key,
                .owner = bpf_loader_program.v3.ID,
                .lamports = 100,
            },
            .{
                .pubkey = system_program.ID,
                .owner = ids.NATIVE_LOADER_ID,
            },
        },
    });
    defer tc.deinit(allocator);

    var ic = InstructionContext{
        .depth = 0,
        .tc = &tc,
        .info = try testing.createInstructionInfo(
            allocator,
            &tc,
            system_program.ID,
            system_program.Instruction{ .assign = .{ .owner = account_key } }, // can be whatever.
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            },
        ),
    };
    defer ic.deinit(allocator);

    const acc_meta = ic.info.account_metas.get(0);
    const acc_shared = ic.tc.accounts[0].account;

    const vm_addr = MM_INPUT_START;
    const data, const region, const account_metadata = try (MockAccountInfo{
        .key = acc_meta.pubkey,
        .is_signer = acc_meta.is_signer,
        .is_writable = acc_meta.is_writable,
        .lamports = acc_shared.lamports,
        .data = acc_shared.data,
        .owner = acc_shared.owner,
        .executable = acc_shared.executable,
        .rent_epoch = acc_shared.rent_epoch,
    }).intoRegion(allocator, vm_addr);
    defer allocator.free(data);

    // NOTE: init aligned false
    // https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L1792
    const memory_map = try MemoryMap.init(&.{region}, .v3);
    
    const account_info = try translateType(AccountInfo, .constant, &memory_map, vm_addr, false);
    var caller_account = try CallerAccount.fromAccountInfo(
        &ic,
        &memory_map,
        account_info,
        &account_metadata,
    );

    try std.testing.expectEqual(caller_account.lamports.*, acc_shared.lamports);
    try std.testing.expect(caller_account.owner.*.equals(&acc_shared.owner));
    try std.testing.expectEqual(caller_account.original_data_len, acc_shared.data.len);
    try std.testing.expectEqual(
        (try caller_account.ref_to_len_in_vm.get(.constant)).*,
        acc_shared.data.len,
    );
    try std.testing.expect(
        std.mem.eql(u8, caller_account.serialized_data, acc_shared.data),
    );

    // test fromSolAccountInfo
    {
        const size = @sizeOf(SolAccountInfo) +
            @sizeOf(Pubkey) * 2 +
            @sizeOf(u64) + 
            acc_shared.data.len;

        const key_offset = @sizeOf(SolAccountInfo);
        const owner_offset = key_offset + @sizeOf(Pubkey);
        const lamports_offset = owner_offset + @sizeOf(Pubkey);
        const data_offset = lamports_offset + @sizeOf(u64);

        const buffer = try allocator.alignedAlloc(u8, @alignOf(SolAccountInfo), size);
        defer allocator.free(buffer);

        // Just have VM memory point to host memory.
        const sol_vm_addr: u64 = @intFromPtr(buffer.ptr);
        buffer[sol_vm_addr + key_offset..][0..@sizeOf(Pubkey)].* = @bitCast(acc_meta.pubkey);
        buffer[sol_vm_addr + owner_offset..][0..@sizeOf(Pubkey)].* = @bitCast(acc_shared.owner);
        buffer[sol_vm_addr + lamports_offset..][0..@sizeOf(u64)].* = @bitCast(acc_shared.lamports);
        @memcpy(buffer[sol_vm_addr + data_offset..][0..acc_shared.data.len], acc_shared.data);

        buffer[0..@sizeOf(SolAccountInfo)].* = @bitCast(SolAccountInfo{
            .key_addr = sol_vm_addr + key_offset,
            .lamports_addr = sol_vm_addr + lamports_offset,
            .data_len = acc_shared.data.len,
            .data_addr = sol_vm_addr + data_offset,
            .owner_addr = sol_vm_addr + owner_offset,
            .rent_epoch = acc_shared.rent_epoch,
            .is_signer = acc_meta.is_signer,
            .is_writable = acc_meta.is_writable,
            .executable = acc_shared.executable,
        });

        const sol_account_metadata = SerializedAccountMetadata{
            .original_data_len = buffer.len,
            .vm_data_addr = sol_vm_addr + data_offset,
            .vm_key_addr = sol_vm_addr + key_offset,
            .vm_lamports_addr = sol_vm_addr + lamports_offset,
            .vm_owner_addr = sol_vm_addr + owner_offset,
        };

        const sol_region = memory.Region.init(.mutable, buffer, sol_vm_addr);
        const sol_memory_map = try memory.MemoryMap.init(&.{sol_region}, .v3);

        const sol_account_info = try translateType(
            SolAccountInfo,
            .constant,
            &sol_memory_map,
            sol_vm_addr,
            false,
        );

        caller_account = try CallerAccount.fromSolAccountInfo(
            &ic,
            &memory_map,
            sol_vm_addr,
            sol_account_info,
            &sol_account_metadata,
        );

        try std.testing.expectEqual(caller_account.lamports.*, acc_shared.lamports);
        try std.testing.expect(caller_account.owner.*.equals(&acc_shared.owner));
        try std.testing.expectEqual(caller_account.original_data_len, acc_shared.data.len);
        try std.testing.expectEqual(
            (try caller_account.ref_to_len_in_vm.get(.constant)).*,
            acc_shared.data.len,
        );
        try std.testing.expect(
            std.mem.eql(u8, caller_account.serialized_data, acc_shared.data),
        );
    }
}
