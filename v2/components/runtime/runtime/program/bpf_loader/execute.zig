const builtin = @import("builtin");
const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../../../component.zig");
const solana = @import("lib").solana;

const ids = sig.runtime.ids;
const bincode = sig.bincode;
const program = sig.runtime.program;
const pubkey_utils = sig.runtime.pubkey_utils;
const sysvar = sig.runtime.sysvar;
const vm = sig.vm;
const bpf_serialize = sig.runtime.program.bpf.serialize;
const system_program = sig.runtime.program.system;
const bpf_loader_program = sig.runtime.program.bpf_loader;
const stable_log = sig.runtime.stable_log;

const Pubkey = solana.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const ExecutionError = sig.vm.ExecutionError;

const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;
const V3State = sig.runtime.program.bpf_loader.v3.State;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "bpf_loader: execute" });
    defer zone.deinit();

    // The borrowed program cannot be held during calls to other execute functions.
    // Agave originally drops it at the relevant sites, but we can just extract needed fields here.
    const program_owner = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();
        break :blk program_account.account.owner;
    };
    const program_id = &ic.ixn_info.program_meta.pubkey;

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/programs/bpf_loader/src/lib.rs#L394-L417
    if (ids.NATIVE_LOADER_ID.equals(&program_owner)) {
        if (bpf_loader_program.v3.ID.equals(program_id)) {
            try ic.tc.consumeCompute(bpf_loader_program.v3.COMPUTE_UNITS);
            return executeBpfLoaderV3ProgramInstruction(allocator, ic);
        } else if (bpf_loader_program.v2.ID.equals(program_id)) {
            try ic.tc.consumeCompute(bpf_loader_program.v2.COMPUTE_UNITS);
            try ic.tc.log("BPF loader management instructions are no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_program.v1.ID.equals(program_id)) {
            try ic.tc.consumeCompute(bpf_loader_program.v1.COMPUTE_UNITS);
            try ic.tc.log("Deprecated loader is no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else {
            try ic.tc.log("Invalid BPF loader id", .{});
            return InstructionError.UnsupportedProgramId;
        }
    }

    // NOTE: We double borrow the program account within `executeBpfProgram`, which adds an
    // additional borrow relative to Agave. This difference should not cause any issues, but is worth noting.
    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L458-L518
    executeBpfProgram(allocator, ic) catch |err| {
        // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L574-L588
        // Agave always logs program failure regardless of error kind.
        try stable_log.programFailure(
            ic.tc,
            ic.ixn_info.program_meta.pubkey,
            err,
        );
        const kind = sig.vm.getExecutionErrorKind(err);
        if (kind != .Instruction) {
            return InstructionError.ProgramFailedToComplete;
        } else {
            return sig.vm.instructionErrorFromExecutionError(err);
        }
    };
}

fn executeBpfProgram(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) ExecutionError!void {
    const executable = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();
        const program_key = program_account.pubkey;

        const loaded_program = ic.tc.program_map.get(program_key) orelse {
            try ic.tc.log("Program is not cached", .{});
            return InstructionError.UnsupportedProgramId;
        };
        switch (loaded_program) {
            .failed => {
                // For the `builtin` case in Agave, they skip the log message
                // and only return `UnsupportedProgramId`. We can emulate the
                // `builtin` program map entry by simply checking if the pubkey
                // is a "builtin program".
                if (program.NATIVE.get(&program_key) == null) {
                    try ic.tc.log("Program is not deployed", .{});
                }
                return InstructionError.UnsupportedProgramId;
            },
            .loaded => |entry| break :blk entry.executable,
        }
    };

    const account_data_direct_mapping = ic.tc.feature_set.active(
        .account_data_direct_mapping,
        ic.tc.slot,
    );
    const virtual_address_space_adjustments = ic.tc.feature_set.active(
        .virtual_address_space_adjustments,
        ic.tc.slot,
    );
    const direct_account_pointers_in_program_input = ic.tc.feature_set.active(
        .direct_account_pointers_in_program_input,
        ic.tc.slot,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1588
    var serialized = try bpf_serialize.serializeParameters(
        allocator,
        ic,
        account_data_direct_mapping,
        virtual_address_space_adjustments,
        direct_account_pointers_in_program_input,
    );
    defer serialized.deinit(allocator);

    // TODO: this is a heavy copy, can we avoid doing it?
    // [agave] https://github.com/anza-xyz/agave/blob/v3.0/programs/bpf_loader/src/lib.rs#L275
    const old_accounts = ic.tc.serialized_accounts;
    ic.tc.serialized_accounts = serialized.account_metas;
    defer ic.tc.serialized_accounts = old_accounts;

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1604-L1617
    // TODO: save account addresses for access violation errors resolution

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1621-L1640
    const compute_available = ic.tc.compute_meter;
    // SIMD-0460: scratch state used by the access-violation handler. It needs
    // a stable address for the whole VM run, hence declared at the outer scope
    // rather than inside the blk.
    var avh_ctx: AccessViolationHandlerCtx = .{
        .tc = ic.tc,
        .allocator = allocator,
        .direct_mapping = account_data_direct_mapping,
    };
    const result, const compute_consumed = blk: {
        var state = sig.vm.init(
            allocator,
            ic.tc,
            &executable,
            serialized.regions.items,
            &ic.tc.vm_environment.loader,
            // SIMD-0321 is now unconditional in agave (no feature gate); always
            // pass the instruction-data offset so r2 is initialized to match.
            // [agave] https://github.com/anza-xyz/agave/blob/v4.1/program-runtime/src/vm.rs#L309
            serialized.instruction_data_offset,
        ) catch |err| {
            try ic.tc.log("Failed to create SBPF VM: {s}", .{@errorName(err)});
            return InstructionError.ProgramEnvironmentSetupFailure;
        };
        defer state.deinit(allocator);

        // SIMD-0460: install the access-violation handler so the VM auto-grows
        // writable+owned account regions on writes within budget, and so we
        // capture failing-access metadata for post-execution error remapping.
        // [agave] https://github.com/anza-xyz/agave/blob/v4.0/program-runtime/src/vm.rs#L111-L119
        if (virtual_address_space_adjustments) {
            ic.tc.last_access_violation = null;
            state.vm.memory_map.setAccessViolationHandler(.{
                .ctx = @ptrCast(&avh_ctx),
                .call = AccessViolationHandlerCtx.handle,
            });
        }

        // Run our bpf program!
        const result = state.vm.run();

        break :blk result;
    };

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1641-L1644
    // TODO: timings

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1646-L1653
    try ic.tc.log("Program {f} consumed {} of {} compute units", .{
        ic.ixn_info.program_meta.pubkey,
        compute_consumed,
        compute_available,
    });

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1653-L1657
    if (ic.tc.return_data.data.len != 0) {
        try stable_log.programReturn(
            ic.tc,
            ic.ixn_info.program_meta.pubkey,
            ic.tc.return_data.data.constSlice(),
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1658-L1731
    var maybe_execute_error: ?ExecutionError = handleExecutionResult(
        result,
        &ic.tc.custom_error,
        &ic.tc.compute_meter,
        ic.tc.feature_set.active(.deplete_cu_meter_on_vm_failure, ic.tc.slot),
    );

    // SIMD-0460: remap a generic AccessViolation to the specific account-data
    // error (`AccountDataTooSmall`, `InvalidRealloc`, `ReadonlyDataModified`,
    // `ExternalAccountDataModified`) using the access metadata captured by
    // the handler. Falls through to AccessViolation when the access doesn't
    // correspond to an account region or no metadata was captured.
    if (virtual_address_space_adjustments) {
        if (maybe_execute_error) |err| if (err == error.AccessViolation) {
            const is_loader_v1 = blk2: {
                const program_account = try ic.borrowProgramAccount();
                defer program_account.release();
                break :blk2 program_account.account.owner.equals(
                    &program.bpf_loader.v1.ID,
                );
            };
            if (remapAccessViolation(ic, is_loader_v1)) |remapped| {
                maybe_execute_error = remapped;
            }
        };
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1750-L1756
    if (maybe_execute_error == null)
        bpf_serialize.deserializeParameters(
            allocator,
            ic,
            virtual_address_space_adjustments,
            account_data_direct_mapping,
            serialized.memory.items,
            serialized.account_metas.constSlice(),
        ) catch |err| {
            maybe_execute_error = err;
        };

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1757-L1761
    // TODO: update timings

    if (maybe_execute_error) |err| return err;
}

fn handleExecutionResult(
    result: sig.vm.interpreter.Result,
    custom_error: *?u32,
    compute_meter: *u64,
    deplete_cu_meter: bool,
) ?ExecutionError {
    switch (result) {
        .ok => |status| if (status != 0) {
            switch (sig.vm.executionErrorFromStatusCode(status)) {
                error.Custom => custom_error.* = @intCast(status),
                error.GenericError => custom_error.* = 0,
                else => |err| return err,
            }
            return error.Custom;
        },
        .err => |err| {
            const err_kind = sig.vm.getExecutionErrorKind(err);
            if (deplete_cu_meter and err_kind != .Syscall)
                compute_meter.* = 0;
            return err;
        },
    }
    return null;
}

/// SIMD-0460: the access-violation handler installed on the VM's memory map
/// while a bpf program runs. Performs Agave-equivalent of
/// `TransactionContext::access_violation_handler`:
///
///   1. Records the failing access (`access_type`, `vm_addr`, `len`) on
///      `tc.last_access_violation` so the post-execution path can remap a
///      generic `AccessViolation` to a specific account-related
///      `InstructionError`. Sig keeps this metadata explicitly, unlike Agave,
///      so handled accesses must be marked and ignored later to avoid stale
///      remapping.
///   2. For *writes* to a writable+owned account region whose payload is set,
///      attempts to grow the region (up to the account's reserved address
///      space, `MAX_PERMITTED_DATA_LENGTH`, and the remaining
///      `MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION` budget)
///      and zero-extends the account data — matching SIMD-0460's
///      "extend the account with zeros to the maximum allowed" rule.
///
/// [agave] https://github.com/anza-xyz/agave/blob/v4.0/transaction-context/src/transaction.rs#L519-L543
pub const AccessViolationHandlerCtx = struct {
    tc: *TransactionContext,
    allocator: std.mem.Allocator,
    direct_mapping: bool,

    pub fn handle(
        ctx_raw: *anyopaque,
        region: *vm.memory.Region,
        address_space_reserved_for_account: u64,
        access_type: vm.memory.MemoryState,
        vm_addr: u64,
        len: u64,
    ) void {
        const ctx: *AccessViolationHandlerCtx = @ptrCast(@alignCast(ctx_raw));

        // Step 1: record for post-execution remapping (always). If the
        // handler later grows the region enough to satisfy this access, the
        // record is marked `handled` so remapAccessViolation can ignore it.
        ctx.tc.last_access_violation = .{
            .access_type = access_type,
            .vm_addr = vm_addr,
            .len = len,
            .handled = false,
        };

        // Step 2: auto-grow logic. Only writable+owned account-data regions
        // are tagged with a payload (see Serializer.writeAccount), so a
        // missing payload means this is not a growable region.
        if (access_type == .constant) return;
        const index_in_transaction = region.access_violation_handler_payload orelse return;

        // Offset of the requested access from this region's start in vm space.
        const requested_length = (vm_addr +| len) -| region.vm_addr_start;
        if (requested_length > address_space_reserved_for_account) {
            // Access exceeds even the maximum reserved address space — the
            // post-execution path will map this to `InvalidRealloc`.
            return;
        }

        const tc_account = ctx.tc.getAccountAtIndex(index_in_transaction) orelse return;
        const account, const guard = tc_account.writeWithLock() orelse return;
        defer guard.release();

        const max_growth =
            sig.runtime.program.system.MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION;
        const remaining_growth: u64 = @intCast(@max(
            0,
            max_growth -| ctx.tc.accounts_resize_delta,
        ));

        // Gate on the region's currently-visible length (agave's `region.len`)
        // rather than `account.data.len` — the slice's `.len` is what the VM
        // sees. `constSlice` reads the length regardless of mutability so this
        // stays correct if CoW later produces a `.constant` payload-tagged
        // region (see serialize.zig `getAccountDataRegionMemoryState` TODO).
        if (requested_length > region.constSlice().len) {
            const old_len: u64 = account.data.len;
            const new_len_u64 = @min(
                address_space_reserved_for_account,
                @min(
                    sig.runtime.program.system.MAX_PERMITTED_DATA_LENGTH,
                    old_len +| remaining_growth,
                ),
            );
            // If we can't grow far enough to cover the access, leave the
            // region untouched — the access violation fires and the
            // post-execution path maps it to `InvalidRealloc`.
            if (new_len_u64 < requested_length) return;

            const new_len: usize = @intCast(new_len_u64);
            account.resize(ctx.allocator, new_len) catch return;
            ctx.tc.accounts_resize_delta +|=
                @as(i64, @intCast(new_len)) -| @as(i64, @intCast(old_len));

            // Non-direct-mapping: extend the slice into the
            // `MAX_PERMITTED_DATA_INCREASE` zeros pre-allocated after the
            // account payload during serialization. Direct-mapping is
            // re-anchored below, mirroring agave's CoW/writable block.
            if (!ctx.direct_mapping) {
                const ptr = region.host_memory.mutable.ptr;
                region.host_memory = .{ .mutable = ptr[0..new_len] };
            }
            region.vm_addr_end = region.vm_addr_start +| @as(u64, new_len);
            // The originally failing access can now succeed on retry, so the
            // recorded metadata is stale for post-execution remapping.
            if (ctx.tc.last_access_violation) |*av| av.handled = true;
        }

        // Direct-mapping: re-anchor `host_memory` to `account.data`.
        // [agave] https://github.com/anza-xyz/agave/blob/v4.0/transaction-context/src/transaction.rs#L541-L543
        if (ctx.direct_mapping) {
            region.host_memory = .{ .mutable = account.data };
        }
    }
};

/// SIMD-0460: convert a generic `AccessViolation` from the SBPF VM into a
/// specific account-related `InstructionError` using the access metadata
/// recorded by `AccessViolationHandlerCtx.handle`. Returns null if the
/// violation does not correspond to an account region (in which case the
/// caller keeps the original `AccessViolation`).
///
/// [agave] https://github.com/anza-xyz/agave/blob/v4/program-runtime/src/vm.rs#L318-L381
fn remapAccessViolation(
    ic: *InstructionContext,
    is_loader_v1: bool,
) ?InstructionError {
    const av = ic.tc.last_access_violation orelse return null;
    // Sig stores the last attempted access explicitly. If the handler already
    // repaired it by growing the region, skip remapping so stale metadata does
    // not misclassify a later real access violation.
    if (av.handled) return null;

    const account_metas = ic.tc.serialized_accounts.constSlice();
    for (account_metas, 0..) |meta, index_in_instruction| {
        // Reserved address space for this account: the original data length
        // plus the growth pad (everywhere except loader-v1, which doesn't
        // reserve growth space).
        const reserved: u64 = if (is_loader_v1)
            meta.original_data_len
        else
            meta.original_data_len +| @as(u64, bpf_serialize.MAX_PERMITTED_DATA_INCREASE);
        const range_start = meta.vm_data_addr;
        const range_end = range_start +| reserved;

        const access_end = av.vm_addr +| av.len;
        if (av.vm_addr < range_start or access_end > range_end) continue;

        // The access fell within this account's reserved range. Was it
        // beyond the account's current data length?
        var account =
            ic.borrowInstructionAccount(@intCast(index_in_instruction)) catch return null;
        defer account.release();
        const requested_offset = access_end -| range_start;
        const is_outside_of_data = requested_offset > account.constAccountData().len;
        const writable = account.checkDataIsMutable() == null;

        return switch (av.access_type) {
            .mutable => if (account.checkDataIsMutable()) |err|
                err
            else if (is_outside_of_data)
                // The store was permitted by the writability check but
                // exceeded the growable range — must have been a grow attempt
                // that the handler refused (out of budget / past the reserved
                // address space).
                InstructionError.InvalidRealloc
            else
                null,
            .constant => if (!writable)
                // Read past the end of a readonly account's data.
                InstructionError.AccountDataTooSmall
            else
                // Read past a writable account's data is also treated as a
                // grow attempt (per Agave / SIMD-0460).
                InstructionError.InvalidRealloc,
        };
    }
    return null;
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L486
pub fn executeBpfLoaderV3ProgramInstruction(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    var buf: [sig.core.Transaction.MAX_BYTES]u8 = undefined;
    const instruction = try ic.ixn_info.limitedDeserializeInstruction(
        bpf_loader_program.v3.Instruction,
        &buf,
    );

    return switch (instruction) {
        .initialize_buffer => executeV3InitializeBuffer(
            allocator,
            ic,
        ),
        .write => |args| executeV3Write(
            allocator,
            ic,
            args.offset,
            args.bytes,
        ),
        .deploy_with_max_data_len => |args| executeV3DeployWithMaxDataLen(
            allocator,
            ic,
            args.max_data_len,
        ),
        .upgrade => executeV3Upgrade(
            allocator,
            ic,
        ),
        .set_authority => executeV3SetAuthority(
            allocator,
            ic,
        ),
        .set_authority_checked => executeV3SetAuthorityChecked(
            allocator,
            ic,
        ),
        .close => executeV3Close(
            allocator,
            ic,
        ),
        .extend_program => |args| executeV3ExtendProgram(
            allocator,
            ic,
            args.additional_bytes,
        ),
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L496-L513
pub fn executeV3InitializeBuffer(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.InitializeBuffer.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(2);

    var buffer_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer buffer_account.release();
    const buffer_account_state = try buffer_account.deserializeFromAccountData(
        allocator,
        V3State,
    );

    if (buffer_account_state != V3State.uninitialized) {
        try ic.tc.log("Buffer account already initialized", .{});
        return InstructionError.AccountAlreadyInitialized;
    }

    const authority_key = ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.authority));
    try buffer_account.serializeIntoAccountData(V3State{
        .buffer = .{
            .authority_address = authority_key,
        },
    });
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L514-L545
pub fn executeV3Write(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    offset: u32,
    bytes: []const u8,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.Write.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(2);

    var buffer_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer buffer_account.release();

    switch (try buffer_account.deserializeFromAccountData(allocator, V3State)) {
        .buffer => |state| {
            if (state.authority_address) |buffer_authority| {
                if (!buffer_authority.equals(
                    &ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.authority)),
                )) {
                    try ic.tc.log("Incorrect buffer authority provided", .{});
                    return InstructionError.IncorrectAuthority;
                }

                if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.authority)))) {
                    try ic.tc.log("Buffer authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            } else {
                try ic.tc.log("Buffer is immutable", .{});
                return InstructionError.Immutable;
            }
        },
        else => {
            try ic.tc.log("Invalid Buffer account", .{});
            return InstructionError.InvalidAccountData;
        },
    }

    const data = try buffer_account.mutableAccountData();
    const start = V3State.BUFFER_METADATA_SIZE +| @as(usize, offset);
    const end = start +| bytes.len;

    if (data.len < end) {
        try ic.tc.log("Write overflow: {} < {}", .{ bytes.len, end });
        return InstructionError.AccountDataTooSmall;
    }

    @memcpy(data[start..end], bytes);
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L546-L720
pub fn executeV3DeployWithMaxDataLen(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    max_data_len: u64,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.DeployWithMaxDataLen.AccountIndex;
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L565
    try ic.ixn_info.checkNumberOfAccounts(4);

    // Safety: at least 4 accounts are present
    const payer_key =
        ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.payer));
    const program_data_key =
        ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.program_data));

    const rent = try ic.getSysvarWithAccountCheck(
        sysvar.Rent,
        @intFromEnum(AccountIndex.rent),
    );
    const clock = try ic.getSysvarWithAccountCheck(
        sysvar.Clock,
        @intFromEnum(AccountIndex.clock),
    );

    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L575
    try ic.ixn_info.checkNumberOfAccounts(8);

    // Safety: at least 8 accounts are present
    const authority_key = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.authority),
    );

    // Verify program account and retrieve its program id
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L582-L597
    const new_program_id = blk: {
        const program_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program),
        );
        defer program_account.release();

        const program_state =
            try program_account.deserializeFromAccountData(allocator, V3State);

        if (program_state != V3State.uninitialized) {
            try ic.tc.log("Program account already initialized", .{});
            return InstructionError.AccountAlreadyInitialized;
        }

        if (program_account.constAccountData().len < V3State.PROGRAM_SIZE) {
            try ic.tc.log("Program account too small", .{});
            return InstructionError.AccountDataTooSmall;
        }

        if (program_account.account.lamports <
            rent.minimumBalance(program_account.constAccountData().len))
        {
            try ic.tc.log("Program account not rent-exempt", .{});
            return InstructionError.ExecutableAccountNotRentExempt;
        }

        break :blk program_account.pubkey;
    };

    // Verify buffer account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L601-L638
    const program_data_len = V3State.PROGRAM_DATA_METADATA_SIZE +| max_data_len;
    {
        const buffer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer_account.release();

        if (!buffer_account.context.is_writable) {
            try ic.tc.log("Buffer account not writeable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!buffer_account.isOwnedByCurrentProgram()) {
            try ic.tc.log("Buffer account not owned by loader", .{});
            return InstructionError.IncorrectProgramId;
        }

        switch (try buffer_account.deserializeFromAccountData(
            allocator,
            V3State,
        )) {
            .buffer => |state| {
                if (state.authority_address == null or
                    !state.authority_address.?.equals(&authority_key))
                {
                    try ic.tc.log("Buffer and upgrade authority don't match", .{});
                    return InstructionError.IncorrectAuthority;
                }

                // Safety: at least 8 accounts are present
                if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.authority)))) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            },
            else => {
                try ic.tc.log("Invalid Buffer account", .{});
                return InstructionError.InvalidArgument;
            },
        }

        const buffer_data = buffer_account.constAccountData();
        if (buffer_data.len <= V3State.BUFFER_METADATA_SIZE) {
            try ic.tc.log("Buffer account too small", .{});
            return InstructionError.InvalidAccountData;
        }

        const buffer_data_len = buffer_data.len -| V3State.BUFFER_METADATA_SIZE;

        if (max_data_len < buffer_data_len) {
            try ic.tc.log("Max data length is too small to hold Buffer data", .{});
            return InstructionError.AccountDataTooSmall;
        }

        if (program_data_len > system_program.MAX_PERMITTED_DATA_LENGTH) {
            try ic.tc.log("Max data length is too large", .{});
            return InstructionError.InvalidArgument;
        }
    }

    // Create the ProgramData account key
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L640-L646
    const derived_key, const bump_seed = pubkey_utils.findProgramAddress(
        &.{&new_program_id.data},
        bpf_loader_program.v3.ID,
    ) orelse {
        // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/pubkey/src/lib.rs#L611-L612
        @panic("Unable to find viable program address bump seed");
    };

    if (!derived_key.equals(&program_data_key)) {
        try ic.tc.log("ProgramData address is not derived", .{});
        return InstructionError.InvalidArgument;
    }

    // Drain the Buffer account to payer before paying for program data account
    {
        var buffer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer_account.release();

        var payer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.payer),
        );
        defer payer_account.release();

        try payer_account.addLamports(buffer_account.account.lamports);
        try buffer_account.setLamports(0);
    }

    // Create the ProgramData account
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L658-L680
    const signer_derived_key = pubkey_utils.createProgramAddress(
        &.{&new_program_id.data},
        &.{bump_seed},
        ic.ixn_info.program_meta.pubkey,
    ) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return InstructionError.Custom;
    };

    try ic.nativeInvoke(
        allocator,
        system_program.ID,
        system_program.Instruction{
            .create_account = .{
                .lamports = @max(1, rent.minimumBalance(program_data_len)),
                .space = program_data_len,
                .owner = ic.ixn_info.program_meta.pubkey,
            },
        },
        &.{
            .{ .pubkey = payer_key, .is_signer = true, .is_writable = true },
            .{ .pubkey = program_data_key, .is_signer = true, .is_writable = true },
            // pass an extra account to avoid the overly strict UnbalancedInstruction error
            // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L668-L669
            .{
                .pubkey = ic.getAccountKeyByIndexUnchecked(
                    @intFromEnum(AccountIndex.buffer),
                ),
                .is_signer = false,
                .is_writable = true,
            },
        },
        &.{signer_derived_key},
    );

    // Load and verify the program bits and deploy the program
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L683-L698
    {
        const buffer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer_account.release();

        const buffer_data = buffer_account.constAccountData();
        if (buffer_data.len < V3State.BUFFER_METADATA_SIZE)
            return InstructionError.AccountDataTooSmall;

        try deployProgram(
            allocator,
            ic.tc,
            new_program_id,
            ic.ixn_info.program_meta.pubkey,
            buffer_data[V3State.BUFFER_METADATA_SIZE..],
            clock.slot,
            ic.tc.feature_set.active(.disable_sbpf_v0_v1_v2_deployment, ic.tc.slot),
        );
    }

    // Update the ProgramData account and record the program bits
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L704-L726
    {
        var program_data_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program_data),
        );
        defer program_data_account.release();
        try program_data_account.serializeIntoAccountData(V3State{
            .program_data = .{
                .slot = clock.slot,
                .upgrade_authority_address = authority_key,
            },
        });
        const program_data = try program_data_account.mutableAccountData();

        var buffer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer_account.release();

        const bytes_to_copy = buffer_account.constAccountData().len - V3State.BUFFER_METADATA_SIZE;

        @memcpy(
            program_data[V3State.PROGRAM_DATA_METADATA_SIZE..][0..bytes_to_copy],
            buffer_account.constAccountData()[V3State.BUFFER_METADATA_SIZE..][0..bytes_to_copy],
        );

        try buffer_account.setDataLength(
            allocator,
            &ic.tc.accounts_resize_delta,
            V3State.BUFFER_METADATA_SIZE,
        );
    }

    // Update the program account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L729-735
    {
        var program_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program),
        );
        defer program_account.release();
        try program_account.serializeIntoAccountData(V3State{ .program = .{
            .programdata_address = program_data_key,
        } });
        try program_account.setExecutable(
            true,
            ic.tc.rent,
        );
    }

    try ic.tc.log("Deployed program {f}", .{new_program_id});
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L705-L894
pub fn executeV3Upgrade(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.Upgrade.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(3);

    const programdata_key =
        ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.program_data));

    const rent = try ic.getSysvarWithAccountCheck(
        sysvar.Rent,
        @intFromEnum(AccountIndex.rent),
    );
    const clock = try ic.getSysvarWithAccountCheck(
        sysvar.Clock,
        @intFromEnum(AccountIndex.clock),
    );

    try ic.ixn_info.checkNumberOfAccounts(7);
    const authority_key = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.authority),
    );

    // Verify program account

    const new_program_id = blk: {
        const program_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program),
        );
        defer program_account.release();

        if (!program_account.context.is_writable) {
            try ic.tc.log("Program account not writeable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!program_account.isOwnedByCurrentProgram()) {
            try ic.tc.log("Program account not owned by loader", .{});
            return InstructionError.IncorrectProgramId;
        }
        switch (try program_account.deserializeFromAccountData(
            allocator,
            V3State,
        )) {
            .program => |data| {
                if (!data.programdata_address.equals(&programdata_key)) {
                    try ic.tc.log("Program and ProgramData account mismatch", .{});
                    return InstructionError.InvalidArgument;
                }
            },
            else => {
                try ic.tc.log("Invalid Program account", .{});
                return InstructionError.InvalidAccountData;
            },
        }
        break :blk program_account.pubkey;
    };

    // Verify buffer account

    const buf = blk: {
        const buffer = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.buffer));
        defer buffer.release();

        if (!buffer.context.is_writable) {
            try ic.tc.log("Buffer account not writeable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!buffer.isOwnedByCurrentProgram()) {
            try ic.tc.log("Buffer account not owned by loader", .{});
            return InstructionError.IncorrectProgramId;
        }

        switch (try buffer.deserializeFromAccountData(allocator, V3State)) {
            .buffer => |data| {
                if (data.authority_address == null or
                    !data.authority_address.?.equals(&authority_key))
                {
                    try ic.tc.log("Buffer and upgrade authority don't match", .{});
                    return InstructionError.IncorrectAuthority;
                }
                if (!(try ic.ixn_info.isIndexSigner(6))) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            },
            else => {
                try ic.tc.log("Invalid Buffer account", .{});
                return InstructionError.InvalidArgument;
            },
        }

        const buf = .{
            .lamports = buffer.account.lamports,
            .data_offset = V3State.BUFFER_METADATA_SIZE,
            .data_len = buffer.constAccountData().len -|
                V3State.BUFFER_METADATA_SIZE,
        };
        if (buffer.constAccountData().len < buf.data_offset or buf.data_len == 0) {
            try ic.tc.log("Buffer account too small", .{});
            return InstructionError.InvalidAccountData;
        }
        break :blk buf;
    };

    // Verify ProgramData account

    const progdata = blk: {
        const programdata =
            try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.program_data));
        defer programdata.release();

        const offset = V3State.PROGRAM_DATA_METADATA_SIZE;
        const balance_required = @max(1, rent.minimumBalance(programdata.constAccountData().len));
        const progdata_size = V3State.sizeOfProgramData(buf.data_len);

        if (programdata.constAccountData().len < progdata_size) {
            try ic.tc.log("ProgramData account not large enough", .{});
            return InstructionError.AccountDataTooSmall;
        }
        if (programdata.account.lamports +| buf.lamports < balance_required) {
            try ic.tc.log("Buffer account balance too low to fund upgrade", .{});
            return InstructionError.InsufficientFunds;
        }

        switch (try programdata.deserializeFromAccountData(
            allocator,
            V3State,
        )) {
            .program_data => |data| {
                if (clock.slot == data.slot) {
                    try ic.tc.log("Program was deployed in this block already", .{});
                    return InstructionError.InvalidArgument;
                }
                if (data.upgrade_authority_address == null) {
                    try ic.tc.log("Program not upgradeable", .{});
                    return InstructionError.Immutable;
                }
                if (!data.upgrade_authority_address.?.equals(&authority_key)) {
                    try ic.tc.log("Incorrect upgrade authority provided", .{});
                    return InstructionError.IncorrectAuthority;
                }
                if (!(try ic.ixn_info.isIndexSigner(6))) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            },
            else => {
                try ic.tc.log("Invalid ProgramData account", .{});
                return InstructionError.InvalidAccountData;
            },
        }

        break :blk .{
            .len = programdata.constAccountData().len,
            .offset = offset,
            .balance_required = balance_required,
        };
    };

    // Load and verify the program bits

    {
        const buffer = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.buffer));
        defer buffer.release();

        if (buffer.constAccountData().len < buf.data_offset) {
            return InstructionError.AccountDataTooSmall;
        }

        try deployProgram(
            allocator,
            ic.tc,
            new_program_id,
            ic.ixn_info.program_meta.pubkey,
            buffer.constAccountData()[buf.data_offset..],
            clock.slot,
            ic.tc.feature_set.active(.disable_sbpf_v0_v1_v2_deployment, ic.tc.slot),
        );
    }

    // Update the ProgramData account, record the upgraded data, and zero the rest:

    var programdata = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.program_data),
    );
    defer programdata.release();

    {
        try programdata.serializeIntoAccountData(V3State{ .program_data = .{
            .slot = clock.slot,
            .upgrade_authority_address = authority_key,
        } });

        const dst_slice = try programdata.mutableAccountData();
        if (dst_slice.len < progdata.offset +| buf.data_len) {
            return InstructionError.AccountDataTooSmall;
        }

        const buffer = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer.release();

        const src_slice = buffer.constAccountData();
        if (src_slice.len < buf.data_offset) {
            return InstructionError.AccountDataTooSmall;
        }

        // copy_from_slice (not using @memcpy as idk if they alias)
        std.mem.copyForwards(
            u8,
            dst_slice[progdata.offset..][0..buf.data_len],
            src_slice[buf.data_offset..],
        );

        // Happens outside this scope but should be the same thing.
        @memset(dst_slice[progdata.offset +| buf.data_len..], 0);
    }

    // Fund ProgramData to rent-exemption, spill the rest
    var buffer = try ic.borrowInstructionAccount(2);
    defer buffer.release();

    var spill = try ic.borrowInstructionAccount(3);
    defer spill.release();

    try spill.addLamports(
        programdata.account.lamports +| buf.lamports -| progdata.balance_required,
    );
    try buffer.setLamports(0);
    try programdata.setLamports(progdata.balance_required);
    try buffer.setDataLength(
        allocator,
        &ic.tc.accounts_resize_delta,
        V3State.sizeOfBuffer(0),
    );

    try ic.tc.log("Upgraded program {f}", .{new_program_id});
}

/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/programs/bpf_loader/src/lib.rs#L946-L1010
pub fn executeV3SetAuthority(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.SetAuthority.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(2);

    var account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer account.release();

    const present_authority_key = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.present_authority),
    );
    const new_authority = if (ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.new_authority),
    )) |meta| meta.pubkey else null;

    switch (try account.deserializeFromAccountData(allocator, V3State)) {
        .buffer => |buffer| {
            if (new_authority == null) {
                try ic.tc.log("Buffer authority is not optional", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (buffer.authority_address == null) {
                try ic.tc.log("Buffer is immutable", .{});
                return InstructionError.Immutable;
            }
            if (!buffer.authority_address.?.equals(&present_authority_key)) {
                try ic.tc.log("Incorrect buffer authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!(try ic.ixn_info.isIndexSigner(1))) {
                try ic.tc.log("Buffer authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(V3State{
                .buffer = .{
                    .authority_address = new_authority,
                },
            });
        },
        .program_data => |data| {
            if (data.upgrade_authority_address == null) {
                try ic.tc.log("Program not upgradeable", .{});
                return InstructionError.Immutable;
            }
            if (!data.upgrade_authority_address.?.equals(&present_authority_key)) {
                try ic.tc.log("Incorrect upgrade authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.present_authority),
            ))) {
                try ic.tc.log("Upgrade authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            // SIMD-0500: forbid finalize (SetAuthority None) on programs whose embedded
            // ELF is older than SBPFv3. Short data short-circuits to OK, matching Agave's
            // let-chain.
            // [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/programs/bpf_loader/src/lib.rs#L580-L591
            if (new_authority == null and
                ic.tc.feature_set.active(.disable_sbpf_v0_v1_v2_deployment, ic.tc.slot))
            {
                const account_data = account.constAccountData();
                const e_flags_offset = V3State.PROGRAM_DATA_METADATA_SIZE + 48;
                if (account_data.len >= e_flags_offset + @sizeOf(u32)) {
                    const e_flags = std.mem.readInt(
                        u32,
                        account_data[e_flags_offset..][0..4],
                        .little,
                    );
                    if (e_flags < @intFromEnum(sig.vm.sbpf.Version.v3)) {
                        return InstructionError.InvalidAccountData;
                    }
                }
            }
            try account.serializeIntoAccountData(V3State{
                .program_data = .{
                    .slot = data.slot,
                    .upgrade_authority_address = new_authority,
                },
            });
        },
        else => {
            try ic.tc.log("Account does not support authorities", .{});
            return InstructionError.InvalidArgument;
        },
    }

    if (new_authority) |some| {
        try ic.tc.log("New authority Some({f})", .{some});
    } else {
        try ic.tc.log("New authority None", .{});
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/programs/bpf_loader/src/lib.rs#L1011-L1083
pub fn executeV3SetAuthorityChecked(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    if (!ic.tc.feature_set.active(.enable_bpf_loader_set_authority_checked_ix, ic.tc.slot)) {
        return InstructionError.InvalidInstructionData;
    }

    const AccountIndex = bpf_loader_program.v3.instruction.SetAuthorityChecked.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(3);

    var account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer account.release();

    const present_authority_key = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.present_authority),
    );
    const new_authority = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.new_authority),
    );

    switch (try account.deserializeFromAccountData(allocator, V3State)) {
        .buffer => |buffer| {
            if (buffer.authority_address == null) {
                try ic.tc.log("Buffer is immutable", .{});
                return InstructionError.Immutable;
            }
            if (!buffer.authority_address.?.equals(&present_authority_key)) {
                try ic.tc.log("Incorrect buffer authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.present_authority),
            ))) {
                try ic.tc.log("Buffer authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.new_authority),
            ))) {
                try ic.tc.log("New authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(V3State{
                .buffer = .{
                    .authority_address = new_authority,
                },
            });
        },
        .program_data => |data| {
            if (data.upgrade_authority_address == null) {
                try ic.tc.log("Program not upgradeable", .{});
                return InstructionError.Immutable;
            }
            if (!data.upgrade_authority_address.?.equals(&present_authority_key)) {
                try ic.tc.log("Incorrect upgrade authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.present_authority),
            ))) {
                try ic.tc.log("Upgrade authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.new_authority),
            ))) {
                try ic.tc.log("New authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(V3State{
                .program_data = .{
                    .slot = data.slot,
                    .upgrade_authority_address = new_authority,
                },
            });
        },
        else => {
            try ic.tc.log("Account does not support authorities", .{});
            return InstructionError.InvalidArgument;
        },
    }

    try ic.tc.log("New authority {f}", .{new_authority});
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L1033-L1138
pub fn executeV3Close(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.Close.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(2);

    const account_index_in_txn = ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.account),
    ).?.index_in_transaction;
    const recipient_index_in_txn = ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.recipient),
    ).?.index_in_transaction;

    if (account_index_in_txn == recipient_index_in_txn) {
        try ic.tc.log("Recipient is the same as the account being closed", .{});
        return InstructionError.InvalidArgument;
    }

    var close_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    var close_account_released = false; // NOTE: used to simulate drop(close_account) below.
    defer if (!close_account_released) close_account.release();

    const close_key = close_account.pubkey;
    const close_account_state = try close_account.deserializeFromAccountData(
        allocator,
        V3State,
    );
    try close_account.setDataLength(
        allocator,
        &ic.tc.accounts_resize_delta,
        V3State.UNINITIALIZED_SIZE,
    );
    switch (close_account_state) {
        .uninitialized => {
            var recipient_account = try ic.borrowInstructionAccount(
                @intFromEnum(AccountIndex.recipient),
            );
            defer recipient_account.release();

            try recipient_account.addLamports(close_account.account.lamports);
            try close_account.setLamports(0);
            try ic.tc.log("Closed Uninitialized {any}", .{close_key});
        },
        .buffer => |data| {
            try ic.ixn_info.checkNumberOfAccounts(3);
            close_account.release();
            close_account_released = true;

            try commonCloseAccount(ic, data.authority_address);
            try ic.tc.log("Closed Buffer {any}", .{close_key});
        },
        .program_data => |data| {
            try ic.ixn_info.checkNumberOfAccounts(4);
            close_account.release();
            close_account_released = true;

            var program_account = try ic.borrowInstructionAccount(
                @intFromEnum(AccountIndex.program),
            );
            var program_account_released = false; // NOTE: simulates drop(program_account) below.
            defer if (!program_account_released) program_account.release();

            const program_key = program_account.pubkey;
            const authority_address = data.upgrade_authority_address;

            if (!program_account.context.is_writable) {
                try ic.tc.log("Program account is not writable", .{});
                return InstructionError.InvalidArgument;
            }
            if (!program_account.isOwnedByCurrentProgram()) {
                try ic.tc.log("Program account not owned by loader", .{});
                return InstructionError.IncorrectProgramId;
            }

            var clock = try ic.tc.sysvar_cache.get(sysvar.Clock);
            if (clock.slot == data.slot) {
                try ic.tc.log("Program was deployed in this block already", .{});
                return InstructionError.InvalidArgument;
            }

            switch (try program_account.deserializeFromAccountData(
                allocator,
                V3State,
            )) {
                .program => |program_data| {
                    if (!program_data.programdata_address.equals(&close_key)) {
                        try ic.tc.log(
                            "ProgramData account does not match ProgramData account",
                            .{},
                        );
                        return InstructionError.InvalidArgument;
                    }

                    program_account.release();
                    program_account_released = true;
                    try commonCloseAccount(ic, authority_address);

                    clock = try ic.tc.sysvar_cache.get(sysvar.Clock);

                    // Remove from the program map if it was deployed.
                    const old_program = try ic.tc.program_map
                        .fetchPut(ic.tc.programs_allocator, program_key, .failed);
                    if (old_program) |p| p.deinit(ic.tc.programs_allocator);
                },
                else => {
                    try ic.tc.log("Invalid Program Account", .{});
                    return InstructionError.InvalidArgument;
                },
            }

            try ic.tc.log("Closed Program {any}", .{program_key});
        },
        else => {
            try ic.tc.log("Account does not support closing", .{});
            return InstructionError.InvalidArgument;
        },
    }
}

fn commonCloseAccount(
    ic: *InstructionContext,
    authority_address: ?Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    if (authority_address == null) {
        try ic.tc.log("Account is immutable", .{});
        return InstructionError.Immutable;
    }

    const AccountIndex = bpf_loader_program.v3.instruction.Close.AccountIndex;
    const auth_account = ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.authority),
    ) orelse return InstructionError.MissingAccount;

    if (!authority_address.?.equals(&auth_account.pubkey)) {
        try ic.tc.log("Incorrect authority provided", .{});
        return InstructionError.IncorrectAuthority;
    }
    if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.authority)))) {
        try ic.tc.log("Authority did not sign", .{});
        return InstructionError.MissingRequiredSignature;
    }

    var close_account = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.account),
    );
    defer close_account.release();

    var recipient_account = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.recipient),
    );
    defer recipient_account.release();

    try recipient_account.addLamports(close_account.account.lamports);
    try close_account.setLamports(0);
    try close_account.serializeIntoAccountData(V3State{ .uninitialized = {} });
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L1158
pub fn executeV3ExtendProgram(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    additional_bytes: u32,
) (error{OutOfMemory} || InstructionError)!void {
    try commonExtendProgram(allocator, ic, additional_bytes);
}

fn commonExtendProgram(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    additional_bytes: u32,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.ExtendProgram.AccountIndex;

    if (additional_bytes == 0) {
        try ic.tc.log("Additional bytes must be greater than 0", .{});
        return InstructionError.InvalidInstructionData;
    }

    var programdata = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.program_data),
    );
    var programdata_released = false; // simulate drop(program_data) down below.
    defer if (!programdata_released) programdata.release();

    const programdata_key = programdata.pubkey;
    if (!programdata.isOwnedByCurrentProgram()) {
        try ic.tc.log("ProgramData owner is invalid", .{});
        return InstructionError.InvalidAccountOwner;
    }
    if (!programdata.context.is_writable) {
        try ic.tc.log("ProgramData is not writable", .{});
        return InstructionError.InvalidArgument;
    }

    const program_key = blk: {
        var program_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program),
        );
        defer program_account.release();

        if (!program_account.context.is_writable) {
            try ic.tc.log("Program account is not writable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!program_account.isOwnedByCurrentProgram()) {
            try ic.tc.log("Program account not owned by loader", .{});
            return InstructionError.InvalidAccountOwner;
        }

        switch (try program_account.deserializeFromAccountData(
            allocator,
            V3State,
        )) {
            .program => |data| {
                if (!data.programdata_address.equals(&programdata_key)) {
                    try ic.tc.log(
                        "Program account does not match ProgramData account",
                        .{},
                    );
                    return InstructionError.InvalidArgument;
                }
            },
            else => {
                try ic.tc.log("Invalid Program account", .{});
                return InstructionError.InvalidAccountData;
            },
        }

        break :blk program_account.pubkey;
    };

    const new_len = programdata.constAccountData().len +| additional_bytes;
    if (new_len > system_program.MAX_PERMITTED_DATA_LENGTH) {
        try ic.tc.log(
            "Extended ProgramData length of {} bytes exceeds max account data length of {}",
            .{ new_len, system_program.MAX_PERMITTED_DATA_LENGTH },
        );
        return InstructionError.InvalidRealloc;
    }

    // [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.1/programs/bpf_loader/src/lib.rs#L861-L883
    if (ic.tc.feature_set.active(.loader_v3_minimum_extend_program_size, ic.tc.slot)) {
        const old_len = programdata.constAccountData().len;
        const headroom = system_program.MAX_PERMITTED_DATA_LENGTH -| old_len;
        const min_bytes = bpf_loader_program.v3.instruction.MINIMUM_EXTEND_PROGRAM_BYTES;
        if (additional_bytes < min_bytes and additional_bytes != headroom) {
            try ic.tc.log(
                "ExtendProgram requires a minimum of {} additional bytes " ++
                    "or to extend to maximum size, but only {} were requested",
                .{ min_bytes, additional_bytes },
            );
            return InstructionError.InvalidArgument;
        }
    }

    const clock_slot = (try ic.tc.sysvar_cache.get(sysvar.Clock)).slot;

    const upgrade_authority_address = switch (try programdata.deserializeFromAccountData(
        allocator,
        V3State,
    )) {
        .program_data => |data| blk: {
            if (clock_slot == data.slot) {
                try ic.tc.log("Program was extended in this block already", .{});
                return InstructionError.InvalidArgument;
            }

            const upgrade_authority_address = data.upgrade_authority_address orelse {
                try ic.tc.log(
                    "Cannot extend ProgramData accounts that are not upgradeable",
                    .{},
                );
                return InstructionError.Immutable;
            };

            break :blk upgrade_authority_address;
        },
        else => {
            try ic.tc.log("ProgramData state is invalid", .{});
            return InstructionError.InvalidAccountData;
        },
    };

    const required_payment = blk: {
        const balance = programdata.account.lamports;
        // [agave] https://github.com/anza-xyz/agave/blob/5fa721b3b27c7ba33e5b0e1c55326241bb403bb1/program-runtime/src/sysvar_cache.rs#L130-L141
        const rent = try ic.tc.sysvar_cache.get(sysvar.Rent);
        const min_balance = @max(1, rent.minimumBalance(new_len));
        break :blk min_balance -| balance;
    };

    // Borrowed accounts need to be dropped before native_invoke
    programdata.release();
    programdata_released = true;

    // Determine the program ID to prevent overlapping mutable/immutable borrow of invoke context.
    if (required_payment > 0) {
        // [agave] https://github.com/anza-xyz/agave/blob/ad0983afd4efa711cf2258aa9630416ed6716d2a/transaction-context/src/lib.rs#L260-L267
        const payer = ic.ixn_info.getAccountMetaAtIndex(
            @intFromEnum(AccountIndex.payer),
        ) orelse
            return InstructionError.MissingAccount;

        try ic.nativeInvoke(
            allocator,
            system_program.ID,
            system_program.Instruction{
                .transfer = .{ .lamports = required_payment },
            },
            &.{
                .{ .pubkey = payer.pubkey, .is_signer = true, .is_writable = true },
                .{ .pubkey = programdata_key, .is_signer = false, .is_writable = true },
            },
            &.{},
        );
    }

    {
        programdata = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program_data),
        );
        defer programdata.release();

        try programdata.setDataLength(allocator, &ic.tc.accounts_resize_delta, new_len);
        const data = programdata.constAccountData();

        try deployProgram(
            allocator,
            ic.tc,
            program_key,
            ic.ixn_info.program_meta.pubkey,
            data[V3State.PROGRAM_DATA_METADATA_SIZE..],
            clock_slot,
            // SIMD-0500: explicitly continue to allow SBPFv0/v1/v2 for ExtendProgram.
            // [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/programs/bpf_loader/src/lib.rs#L971
            false,
        );
    }

    programdata = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.program_data));
    defer programdata.release();

    try programdata.serializeIntoAccountData(V3State{
        .program_data = .{
            .slot = clock_slot,
            .upgrade_authority_address = upgrade_authority_address,
        },
    });

    try ic.tc.log("Extended ProgramData account by {} bytes", .{additional_bytes});
}

/// TODO: This function depends on syscalls and program cache implementations
/// which is are not implemented yet. It does not affect the account state resulting from
/// the execution of bpf loader instructions unless it returns an error.
/// [agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/programs/bpf_loader/src/lib.rs#L115
/// [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/program/fd_bpf_loader_program.c#L238
pub fn deployProgram(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    program_id: Pubkey,
    owner_id: Pubkey,
    data: []const u8,
    deploy_slot: u64,
    disable_sbpf_v0_v1_v2_deployment: bool,
) (error{OutOfMemory} || InstructionError)!void {
    _ = deploy_slot;
    _ = owner_id;

    try verifyProgram(
        allocator,
        data,
        tc.slot,
        tc.feature_set,
        &tc.compute_budget,
        if (tc.log_collector) |*lc| lc else null,
        disable_sbpf_v0_v1_v2_deployment,
    );

    // Remove from the program map since it should not be accessible on this slot anymore.
    if (try tc.program_map.fetchPut(tc.programs_allocator, program_id, .failed)) |old| {
        old.deinit(tc.programs_allocator);
    }
}

pub fn verifyProgram(
    allocator: std.mem.Allocator,
    data: []const u8,
    slot: sig.core.Slot,
    feature_set: *const solana.features.Set,
    compute_budget: *const sig.runtime.ComputeBudget,
    log_collector: ?*sig.runtime.LogCollector,
    disable_sbpf_v0_v1_v2_deployment: bool,
) !void {
    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L124-L131
    var environment = vm.Environment.initV1(
        feature_set,
        compute_budget,
        slot,
        true,
    );

    // SIMD-0500: morph the base environment into a deployment environment.
    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/program-runtime/src/deploy.rs#L30-32
    if (disable_sbpf_v0_v1_v2_deployment) {
        environment.config.minimum_version = @enumFromInt(@max(
            @intFromEnum(environment.config.minimum_version),
            @intFromEnum(sig.vm.sbpf.Version.v3),
        ));
    }

    // Deployment of programs with sol_alloc_free is disabled.
    if (environment.loader.map.get(.sol_alloc_free_) != null) {
        environment.loader.map.set(.sol_alloc_free_, null);
    }

    // Copy the program data to a new buffer
    const source = try allocator.dupe(u8, data);
    defer allocator.free(source);

    var executable = vm.elf.load(
        allocator,
        source,
        &environment.loader,
        environment.config,
    ) catch |err| {
        if (log_collector) |lc| try lc.log(allocator, "{s}", .{@errorName(err)});
        return InstructionError.InvalidAccountData;
    };
    defer executable.deinit(allocator);

    executable.verify() catch |err| {
        if (log_collector) |lc| try lc.log(allocator, "{s}", .{@errorName(err)});
        return InstructionError.InvalidAccountData;
    };
}

test executeV3InitializeBuffer {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_state = V3State.uninitialized;
    const initial_buffer_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_state = V3State{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const final_buffer_account_data = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(final_buffer_account_data);
    @memset(final_buffer_account_data, 0);
    _ = try bincode.writeToSlice(final_buffer_account_data, final_buffer_account_state, .{});

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.initialize_buffer,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test executeV3Write {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const offset = 10;
    const source = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

    const initial_buffer_account_state = V3State{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const initial_buffer_account_data =
        try allocator.alloc(u8, @sizeOf(V3State) + offset + source.len);
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    const start = V3State.BUFFER_METADATA_SIZE + offset;
    const end = start +| source.len;
    @memcpy(final_buffer_account_data[start..end], &source);

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction{
            .write = .{
                .offset = offset,
                .bytes = &source,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test executeV3DeployWithMaxDataLen {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const payer_account_key = Pubkey.initRandom(prng.random());
    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key, _ = pubkey_utils.findProgramAddress(
        &.{&program_account_key.data},
        bpf_loader_program.v3.ID,
    ) orelse @panic("findProgramAddress failed");
    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const rent = sysvar.Rent.INIT;

    const additional_bytes = 1024;

    const initial_program_account_data =
        try allocator.alloc(u8, V3State.PROGRAM_SIZE);
    defer allocator.free(initial_program_account_data);
    @memset(initial_program_account_data, 0);
    _ = try bincode.writeToSlice(
        initial_program_account_data,
        V3State.uninitialized,
        .{},
    );

    const initial_program_account_lamports = rent.minimumBalance(initial_program_account_data.len);

    const final_program_account_data =
        try allocator.alloc(u8, V3State.PROGRAM_SIZE);
    defer allocator.free(final_program_account_data);
    @memset(final_program_account_data, 0);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        V3State{
            .program = .{
                .programdata_address = program_data_account_key,
            },
        },
        .{},
    );

    const initial_buffer_account_data = try createValidProgramData(
        allocator,
        V3State{
            .buffer = .{
                .authority_address = buffer_authority_key,
            },
        },
        V3State.BUFFER_METADATA_SIZE,
        additional_bytes,
    );
    defer allocator.free(initial_buffer_account_data);
    const initial_buffer_account_lamports = 1_000;
    const final_buffer_account_data =
        initial_buffer_account_data[0..V3State.BUFFER_METADATA_SIZE];

    const final_program_data_account_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = 0,
                .upgrade_authority_address = buffer_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        additional_bytes,
    );
    defer allocator.free(final_program_data_account_data);

    try std.testing.expectEqualSlices(
        u8,
        initial_buffer_account_data[V3State.BUFFER_METADATA_SIZE..],
        final_program_data_account_data[V3State.PROGRAM_DATA_METADATA_SIZE..],
    );

    const max_data_len =
        final_program_data_account_data.len -|
        V3State.PROGRAM_DATA_METADATA_SIZE;

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction{
            .deploy_with_max_data_len = .{ .max_data_len = max_data_len },
        },
        &.{
            .{ .index_in_transaction = 0, .is_signer = true, .is_writable = true },
            .{ .index_in_transaction = 1, .is_signer = false, .is_writable = true },
            .{ .index_in_transaction = 2, .is_signer = false, .is_writable = true },
            .{ .index_in_transaction = 3, .is_signer = false, .is_writable = true },
            .{ .index_in_transaction = 4, .is_signer = false, .is_writable = false },
            .{ .index_in_transaction = 5, .is_signer = false, .is_writable = false },
            .{ .index_in_transaction = 6, .is_signer = false, .is_writable = false },
            .{ .index_in_transaction = 7, .is_signer = true, .is_writable = false },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = payer_account_key,
                    .lamports = @max(1, rent.minimumBalance(final_program_data_account_data.len)),
                    .owner = system_program.ID,
                },
                .{
                    .pubkey = program_data_account_key,
                    .owner = system_program.ID,
                },
                .{
                    .pubkey = program_account_key,
                    .lamports = initial_program_account_lamports,
                    .owner = bpf_loader_program.v3.ID,
                    .data = initial_program_account_data,
                },
                .{
                    .pubkey = buffer_account_key,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = initial_buffer_account_lamports,
                    .data = initial_buffer_account_data,
                },
                .{ .pubkey = sysvar.Rent.ID },
                .{ .pubkey = sysvar.Clock.ID },
                .{
                    .pubkey = program.system.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                    .executable = true,
                },
                .{ .pubkey = buffer_authority_key },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .sysvar_cache = .{
                .rent = sysvar.Rent.INIT,
                .clock = sysvar.Clock.INIT,
            },
            // TODO: Should we need extra for system program cpi???
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS + 150,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = payer_account_key,
                    .lamports = initial_buffer_account_lamports,
                    .owner = system_program.ID,
                },
                .{
                    .pubkey = program_data_account_key,
                    .lamports = @max(1, rent.minimumBalance(final_program_data_account_data.len)),
                    .owner = bpf_loader_program.v3.ID,
                    .data = final_program_data_account_data,
                },
                .{
                    .pubkey = program_account_key,
                    .lamports = initial_program_account_lamports,
                    .owner = bpf_loader_program.v3.ID,
                    .data = final_program_account_data,
                    .executable = true,
                },
                .{
                    .pubkey = buffer_account_key,
                    .owner = bpf_loader_program.v3.ID,
                    .data = final_buffer_account_data,
                },
                .{ .pubkey = sysvar.Rent.ID },
                .{ .pubkey = sysvar.Clock.ID },
                .{
                    .pubkey = program.system.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                    .executable = true,
                },
                .{ .pubkey = buffer_authority_key },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .accounts_resize_delta = @intCast(
                final_buffer_account_data.len +
                    V3State.PROGRAM_DATA_METADATA_SIZE +|
                    max_data_len -|
                    initial_buffer_account_data.len,
            ),
            .sysvar_cache = .{
                .rent = sysvar.Rent.INIT,
                .clock = sysvar.Clock.INIT,
            },
        },
        .{},
    );
}

test executeV3SetAuthority {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());
    const new_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_buffer_account_data);
    _ = try bincode.writeToSlice(
        initial_buffer_account_data,
        V3State{
            .buffer = .{ .authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    _ = try bincode.writeToSlice(
        final_buffer_account_data,
        V3State{
            .buffer = .{ .authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.buffer
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID, // id of program u wanna run
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID, // bpf_loader_program.v3.ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );

    const initial_program_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_program_account_data);
    _ = try bincode.writeToSlice(
        initial_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_program_account_data = try allocator.dupe(u8, initial_program_account_data);
    defer allocator.free(final_program_account_data);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.program_data
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID, // id of program u wanna run
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID, // bpf_loader_program.v3.ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );

    @memcpy(final_program_account_data, initial_program_account_data);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = null },
        },
        .{},
    );

    // test with no new authority
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID, // id of program u wanna run
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID, // bpf_loader_program.v3.ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test "executeV3SetAuthority SIMD-0500 finalize guard" {
    const testing = sig.runtime.program.testing;
    const ExecuteContextsParams = sig.runtime.testing.ExecuteContextsParams;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_account_key = Pubkey.initRandom(prng.random());
    const present_authority_key = Pubkey.initRandom(prng.random());

    // Build a ProgramData account that is large enough for the e_flags check
    // (PROGRAM_DATA_METADATA_SIZE + Elf64_Ehdr.e_flags offset (48) + sizeof(u32)).
    const e_flags_offset = V3State.PROGRAM_DATA_METADATA_SIZE + 48;
    const account_size = e_flags_offset + @sizeOf(u32);

    // Helper: create a finalize (SetAuthority None) instruction-account list +
    // initial+final account data buffers with the given e_flags written into them.
    const Case = struct {
        e_flags: u32,
        feature_active: bool,
        expect_error: ?InstructionError,
    };

    const cases: []const Case = &.{
        // SBPFv0 with feature active → finalize forbidden.
        .{
            .e_flags = 0,
            .feature_active = true,
            .expect_error = InstructionError.InvalidAccountData,
        },
        // SBPFv2 with feature active → finalize forbidden.
        .{
            .e_flags = 2,
            .feature_active = true,
            .expect_error = InstructionError.InvalidAccountData,
        },
        // SBPFv3 with feature active → finalize permitted.
        .{ .e_flags = 3, .feature_active = true, .expect_error = null },
        // SBPFv0 with feature inactive → finalize permitted (legacy behaviour).
        .{ .e_flags = 0, .feature_active = false, .expect_error = null },
    };

    for (cases) |c| {
        const initial_data = try allocator.alloc(u8, account_size);
        defer allocator.free(initial_data);
        @memset(initial_data, 0);
        _ = try bincode.writeToSlice(initial_data, V3State{
            .program_data = .{
                .slot = 0,
                .upgrade_authority_address = present_authority_key,
            },
        }, .{});
        std.mem.writeInt(u32, initial_data[e_flags_offset..][0..4], c.e_flags, .little);

        const final_data = try allocator.dupe(u8, initial_data);
        defer allocator.free(final_data);
        _ = try bincode.writeToSlice(final_data, V3State{
            .program_data = .{
                .slot = 0,
                .upgrade_authority_address = null,
            },
        }, .{});

        const feature_params: []const ExecuteContextsParams.FeatureParams =
            if (c.feature_active)
                &.{.{ .feature = .disable_sbpf_v0_v1_v2_deployment, .slot = 0 }}
            else
                &.{};

        const initial_context = ExecuteContextsParams{
            .feature_set = feature_params,
            .accounts = &.{
                .{
                    .pubkey = program_account_key,
                    .data = initial_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{ .pubkey = present_authority_key },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        };
        const expected_context = ExecuteContextsParams{
            .feature_set = feature_params,
            .accounts = &.{
                .{
                    .pubkey = program_account_key,
                    .data = final_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{ .pubkey = present_authority_key },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        };

        if (c.expect_error) |err| {
            try testing.expectProgramExecuteError(
                err,
                allocator,
                bpf_loader_program.v3.ID,
                bpf_loader_program.v3.Instruction.set_authority,
                &.{
                    .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                    .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
                },
                initial_context,
                .{},
            );
        } else {
            try testing.expectProgramExecuteResult(
                allocator,
                bpf_loader_program.v3.ID,
                bpf_loader_program.v3.Instruction.set_authority,
                &.{
                    .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                    .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
                },
                initial_context,
                expected_context,
                .{},
            );
        }
    }

    // Short-data short-circuit: the account is shorter than the e_flags offset, so
    // even with the feature active and an SBPFv0-shaped flag we still allow the
    // finalize. Mirrors Agave's let-chain that yields `Some(true)` only when
    // both slice and parse succeed.
    {
        const short_size = V3State.PROGRAM_DATA_METADATA_SIZE; // no ELF bytes at all
        const initial_data = try allocator.alloc(u8, short_size);
        defer allocator.free(initial_data);
        @memset(initial_data, 0);
        _ = try bincode.writeToSlice(initial_data, V3State{
            .program_data = .{
                .slot = 0,
                .upgrade_authority_address = present_authority_key,
            },
        }, .{});

        const final_data = try allocator.dupe(u8, initial_data);
        defer allocator.free(final_data);
        _ = try bincode.writeToSlice(final_data, V3State{
            .program_data = .{
                .slot = 0,
                .upgrade_authority_address = null,
            },
        }, .{});

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction.set_authority,
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            },
            .{
                .feature_set = &.{
                    .{ .feature = .disable_sbpf_v0_v1_v2_deployment, .slot = 0 },
                },
                .accounts = &.{
                    .{
                        .pubkey = program_account_key,
                        .data = initial_data,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{ .pubkey = present_authority_key },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            },
            .{
                .feature_set = &.{
                    .{ .feature = .disable_sbpf_v0_v1_v2_deployment, .slot = 0 },
                },
                .accounts = &.{
                    .{
                        .pubkey = program_account_key,
                        .data = final_data,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{ .pubkey = present_authority_key },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                    },
                },
            },
            .{},
        );
    }
}

test executeV3SetAuthorityChecked {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());
    const new_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_buffer_account_data);
    _ = try bincode.writeToSlice(
        initial_buffer_account_data,
        V3State{
            .buffer = .{ .authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    _ = try bincode.writeToSlice(
        final_buffer_account_data,
        V3State{
            .buffer = .{ .authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.buffer (1 and 2 must be signers).
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority_checked,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID, // id of program u wanna run
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID, // bpf_loader_program.v3.ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            .feature_set = &.{
                .{
                    .feature = .enable_bpf_loader_set_authority_checked_ix,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );

    const initial_program_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_program_account_data);
    _ = try bincode.writeToSlice(
        initial_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_program_account_data = try allocator.dupe(u8, initial_program_account_data);
    defer allocator.free(final_program_account_data);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.program_data (1 and 2 must be signers).
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority_checked,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            .feature_set = &.{
                .{
                    .feature = .enable_bpf_loader_set_authority_checked_ix,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test executeV3Close {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const close_account_key = Pubkey.initRandom(prng.random());
    const repicient_key = Pubkey.initRandom(prng.random());
    const authority_key = Pubkey.initRandom(prng.random());
    const program_key = Pubkey.initRandom(prng.random());

    const initial_account_data = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_account_data);
    const final_account_data = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(final_account_data);

    const num_lamports = 42 + prng.random().uintAtMost(u64, 1337);

    // uninitialized
    {
        const uninitialized_data = try bincode.writeToSlice(
            initial_account_data,
            V3State{ .uninitialized = {} },
            .{},
        );

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .close = .{},
            },
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = true, .is_writable = true, .index_in_transaction = 1 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = uninitialized_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = repicient_key,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = uninitialized_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = repicient_key,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
            },
            .{},
        );
    }

    // buffer
    {
        const initial_data = try bincode.writeToSlice(
            initial_account_data,
            V3State{
                .buffer = .{
                    .authority_address = authority_key,
                },
            },
            .{},
        );

        const final_data = try bincode.writeToSlice(
            final_account_data,
            V3State{ .uninitialized = {} },
            .{},
        );

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .close = .{},
            },
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = initial_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = repicient_key,
                    },
                    .{
                        .pubkey = authority_key,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = final_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = repicient_key,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = authority_key,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .accounts_resize_delta = -@as(i64, @intCast(initial_data.len - final_data.len)),
            },
            .{},
        );
    }

    // program_data
    {
        var clock = sysvar.Clock.INIT;
        clock.slot = 1337;

        const initial_data = try bincode.writeToSlice(
            initial_account_data,
            V3State{
                .program_data = .{
                    .slot = clock.slot - 1,
                    .upgrade_authority_address = authority_key,
                },
            },
            .{},
        );

        const final_data = try bincode.writeToSlice(
            final_account_data,
            V3State{ .uninitialized = {} },
            .{},
        );

        const program_data_buffer = try allocator.alloc(u8, @sizeOf(V3State));
        defer allocator.free(program_data_buffer);
        const program_data = try bincode.writeToSlice(
            program_data_buffer,
            V3State{
                .program = .{ .programdata_address = close_account_key },
            },
            .{},
        );

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .close = .{},
            },
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 3 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = initial_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = repicient_key,
                    },
                    .{
                        .pubkey = authority_key,
                    },
                    .{
                        .pubkey = program_key,
                        .data = program_data,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
                .sysvar_cache = .{
                    .clock = clock,
                },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = final_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = repicient_key,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = authority_key,
                    },
                    .{
                        .pubkey = program_key,
                        .data = program_data,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .accounts_resize_delta = -@as(i64, @intCast(initial_data.len - final_data.len)),
            },
            .{},
        );
    }
}

test executeV3Upgrade {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const spill_account_key = Pubkey.initRandom(prng.random());
    const upgrade_authority_key = Pubkey.initRandom(prng.random());
    const buffer_account_key = Pubkey.initRandom(prng.random());

    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key, _ = pubkey_utils.findProgramAddress(
        &.{&program_account_key.data},
        bpf_loader_program.v3.ID,
    ) orelse @panic("findProgramAddress failed");

    const rent = sysvar.Rent.INIT;
    var clock = sysvar.Clock.INIT;
    clock.slot += 1337;

    // const buf_size = 512;

    const initial_program_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = clock.slot - 1,
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        0,
    );
    defer allocator.free(initial_program_data);

    const updated_program_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = clock.slot,
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        0,
    );
    defer allocator.free(updated_program_data);

    const program_account_buffer = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(program_account_buffer);
    _ = try bincode.writeToSlice(
        program_account_buffer,
        V3State{
            .program = .{ .programdata_address = program_data_account_key },
        },
        .{},
    );

    const buffer_account_data = try createValidProgramData(
        allocator,
        V3State{
            .buffer = .{ .authority_address = upgrade_authority_key },
        },
        V3State.BUFFER_METADATA_SIZE,
        0,
    );
    defer allocator.free(buffer_account_data);

    const buffer_aid_balance = 42;
    const spill_balance = 100;
    const buffer_balance = rent.minimumBalance(buffer_account_data.len) + buffer_aid_balance;
    const program_data_balance = rent.minimumBalance(initial_program_data.len) - buffer_aid_balance;
    const expected_account_resize_delta: i64 =
        @intCast(buffer_account_data.len - V3State.BUFFER_METADATA_SIZE);

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction{
            .upgrade = .{},
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 2 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 3 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 5 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 6 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_data_account_key,
                    .data = initial_program_data,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = program_data_balance,
                },
                .{
                    .pubkey = program_account_key,
                    .data = program_account_buffer,
                    .owner = bpf_loader_program.v3.ID,
                    .executable = true,
                },
                .{
                    .pubkey = buffer_account_key,
                    .data = buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = buffer_balance,
                },
                .{
                    .pubkey = spill_account_key,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = spill_balance,
                },
                .{
                    .pubkey = sysvar.Rent.ID,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = sysvar.Clock.ID,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = upgrade_authority_key,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_data_account_key,
                    .data = updated_program_data,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = rent.minimumBalance(updated_program_data.len),
                },
                .{
                    .pubkey = program_account_key,
                    .data = program_account_buffer,
                    .owner = bpf_loader_program.v3.ID,
                    .executable = true,
                },
                .{
                    .pubkey = buffer_account_key,
                    .data = buffer_account_data[0..V3State.BUFFER_METADATA_SIZE],
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = 0,
                },
                .{
                    .pubkey = spill_account_key,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = spill_balance +
                        buffer_balance +
                        program_data_balance -
                        rent.minimumBalance(initial_program_data.len),
                },
                .{
                    .pubkey = sysvar.Rent.ID,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = sysvar.Clock.ID,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = upgrade_authority_key,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .accounts_resize_delta = -expected_account_resize_delta,
        },
        .{},
    );
}

test executeV3ExtendProgram {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const payer_account_key = Pubkey.initRandom(prng.random());
    const upgrade_authority_key = Pubkey.initRandom(prng.random());

    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key, _ = pubkey_utils.findProgramAddress(
        &.{&program_account_key.data},
        bpf_loader_program.v3.ID,
    ) orelse @panic("findProgramAddress failed");

    var clock = sysvar.Clock.INIT;
    clock.slot += 1337;

    const initial_program_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = clock.slot - 1,
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        0,
    );
    defer allocator.free(initial_program_data);

    const additional_bytes = 512;
    const final_program_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = clock.slot,
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        additional_bytes,
    );
    defer allocator.free(final_program_data);

    const program_account_buffer = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(program_account_buffer);
    const program_account = try bincode.writeToSlice(
        program_account_buffer,
        V3State{
            .program = .{ .programdata_address = program_data_account_key },
        },
        .{},
    );

    // Test with and without the payer helping out to pay for extend.
    for ([_]u32{ 0, 100 }) |help_pay| {
        std.debug.assert(help_pay < additional_bytes);

        const payer_balance = prng.random().uintAtMost(u32, 1024) + help_pay;
        const program_data_lamports =
            sysvar.Rent.INIT.minimumBalance(initial_program_data.len + additional_bytes) -
            help_pay;

        var compute_units: u64 = bpf_loader_program.v3.COMPUTE_UNITS;
        if (help_pay > 0) { // triggers native cpi transfer call
            compute_units += system_program.COMPUTE_UNITS;
        }

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .extend_program = .{ .additional_bytes = additional_bytes },
            },
            &.{
                // program_data
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                // program
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
                // system_program
                .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
                // payer
                .{ .is_signer = true, .is_writable = true, .index_in_transaction = 4 },
                // bpf program_id (for instruction)
                .{ .is_signer = false, .is_writable = false, .index_in_transaction = 5 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = program_data_account_key,
                        .data = initial_program_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = program_data_lamports,
                    },
                    .{
                        .pubkey = program_account_key,
                        .data = program_account,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = upgrade_authority_key,
                        .owner = system_program.ID,
                    },
                    .{
                        .pubkey = system_program.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                        .executable = true,
                    },
                    .{
                        .pubkey = payer_account_key,
                        .lamports = payer_balance,
                        .owner = system_program.ID,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = compute_units,
                .sysvar_cache = .{
                    .rent = sysvar.Rent.INIT,
                    .clock = clock,
                },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = program_data_account_key,
                        .data = final_program_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = program_data_lamports + help_pay,
                    },
                    .{
                        .pubkey = program_account_key,
                        .data = program_account,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = upgrade_authority_key,
                        .owner = system_program.ID,
                    },
                    .{
                        .pubkey = system_program.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                        .executable = true,
                    },
                    .{
                        .pubkey = payer_account_key,
                        .lamports = payer_balance - help_pay,
                        .owner = system_program.ID,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .accounts_resize_delta = additional_bytes,
            },
            .{},
        );
    }
}

// SIMD-0431: extending by fewer than 10240 bytes (and not the headroom amount) must be
// rejected with `InvalidArgument` when `loader_v3_minimum_extend_program_size` is active.
test "executeV3ExtendProgram SIMD-0431 minimum_extend_program_size" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const payer_account_key = Pubkey.initRandom(prng.random());
    const upgrade_authority_key = Pubkey.initRandom(prng.random());

    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key, _ = pubkey_utils.findProgramAddress(
        &.{&program_account_key.data},
        bpf_loader_program.v3.ID,
    ) orelse @panic("findProgramAddress failed");

    var clock = sysvar.Clock.INIT;
    clock.slot += 1337;

    const initial_program_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = clock.slot - 1,
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        0,
    );
    defer allocator.free(initial_program_data);

    const program_account_buffer = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(program_account_buffer);
    const program_account = try bincode.writeToSlice(
        program_account_buffer,
        V3State{
            .program = .{ .programdata_address = program_data_account_key },
        },
        .{},
    );

    const additional_bytes: u32 = 1;
    const program_data_lamports =
        sysvar.Rent.INIT.minimumBalance(initial_program_data.len + additional_bytes);
    const payer_balance = prng.random().uintAtMost(u32, 1024);

    const accounts = [_]sig.runtime.testing.ExecuteContextsParams.AccountParams{
        .{
            .pubkey = program_data_account_key,
            .data = initial_program_data,
            .owner = bpf_loader_program.v3.ID,
            .lamports = program_data_lamports,
        },
        .{
            .pubkey = program_account_key,
            .data = program_account,
            .owner = bpf_loader_program.v3.ID,
        },
        .{
            .pubkey = upgrade_authority_key,
            .owner = system_program.ID,
        },
        .{
            .pubkey = system_program.ID,
            .owner = ids.NATIVE_LOADER_ID,
            .executable = true,
        },
        .{
            .pubkey = payer_account_key,
            .lamports = payer_balance,
            .owner = system_program.ID,
        },
        .{
            .pubkey = bpf_loader_program.v3.ID,
            .owner = ids.NATIVE_LOADER_ID,
        },
    };

    const instruction_accounts = [_]testing.InstructionContextAccountMetaParams{
        // program_data
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        // program
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
        // system_program
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
        // payer
        .{ .is_signer = true, .is_writable = true, .index_in_transaction = 4 },
        // bpf program_id (for instruction)
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 5 },
    };

    // (a) feature ACTIVE + additional_bytes < MINIMUM_EXTEND_PROGRAM_BYTES → InvalidArgument
    try testing.expectProgramExecuteError(
        InstructionError.InvalidArgument,
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction{
            .extend_program = .{ .additional_bytes = additional_bytes },
        },
        &instruction_accounts,
        .{
            .accounts = &accounts,
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = sysvar.Rent.INIT,
                .clock = clock,
            },
            .feature_set = &.{
                .{ .feature = .loader_v3_minimum_extend_program_size, .slot = 0 },
            },
        },
        .{},
    );
}

fn createValidProgramData(
    allocator: std.mem.Allocator,
    state: anytype,
    state_size: usize,
    additional_bytes: usize,
) ![]u8 {
    if (!builtin.is_test)
        @compileError("createValidProgramData should only be used in tests");

    const elf_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        1024 * 1024,
    );
    defer allocator.free(elf_bytes);

    const program_data =
        try allocator.alloc(
            u8,
            state_size + elf_bytes.len + additional_bytes,
        );
    errdefer allocator.free(program_data);
    @memset(program_data, 0);

    _ = try bincode.writeToSlice(
        program_data[0..state_size],
        state,
        .{},
    );

    @memcpy(
        program_data[state_size .. program_data.len - additional_bytes],
        elf_bytes,
    );

    return program_data;
}

test handleExecutionResult {
    var custom_error: ?u32 = null;
    var compute_meter: u64 = 1000;

    // No Error
    try std.testing.expectEqual(null, handleExecutionResult(
        .{ .ok = 0 },
        &custom_error,
        &compute_meter,
        false,
    ));
    try std.testing.expectEqual(null, custom_error);
    try std.testing.expectEqual(1000, compute_meter);

    // Generic Error maps to Custom error with code 0
    try std.testing.expectEqual(error.Custom, handleExecutionResult(
        .{ .ok = 0x100000000 },
        &custom_error,
        &compute_meter,
        false,
    ).?);
    try std.testing.expectEqual(0, custom_error.?);
    try std.testing.expectEqual(1000, compute_meter);

    // Custom error with specific code
    custom_error = null;
    try std.testing.expectEqual(error.Custom, handleExecutionResult(
        .{ .ok = 101 },
        &custom_error,
        &compute_meter,
        false,
    ).?);
    try std.testing.expectEqual(101, custom_error.?);
    try std.testing.expectEqual(1000, compute_meter);

    // Deplete compute meter on non-syscall error
    custom_error = null;
    try std.testing.expectEqual(error.InvalidArgument, handleExecutionResult(
        .{ .err = error.InvalidArgument },
        &custom_error,
        &compute_meter,
        true,
    ).?);
    try std.testing.expectEqual(null, custom_error);
    try std.testing.expectEqual(0, compute_meter);

    // AccessViolation is returned unchanged at this layer; SIMD-0460 remapping
    // happens in executeBpfProgram (which has the InstructionContext + access
    // metadata from `TransactionContext.last_access_violation`).
}

// SIMD-0460: covers `AccessViolationHandlerCtx.handle` — the function the SBPF
// VM calls when an access misses, which both records metadata for post-execution
// error remapping and (for writes within budget) auto-grows the account-data
// region. Exercises each early-return guard plus the successful-grow path under
// both direct- and non-direct-mapping.
test "AccessViolationHandlerCtx.handle" {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const account_data_size: usize = 100;
    const initial_data = try allocator.alloc(u8, account_data_size);
    defer allocator.free(initial_data);
    @memset(initial_data, 0xab);

    const program_id = Pubkey.initRandom(prng.random());
    const data_account_key = Pubkey.initRandom(prng.random());

    const cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{
            .{ .pubkey = data_account_key, .data = initial_data, .owner = program_id },
            .{ .pubkey = program_id, .owner = sig.runtime.ids.NATIVE_LOADER_ID },
        },
    });
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        testing.deinitAccountMap(cache, allocator);
    }

    // Non-direct-mapping host buffer: serializer pre-reserves MAX_PERMITTED_DATA_INCREASE
    // bytes of zero-padding past the account payload, so the handler can extend
    // the region's host slice into that padding without reallocating.
    const region_buffer_size: usize =
        account_data_size + bpf_serialize.MAX_PERMITTED_DATA_INCREASE;
    const region_buffer = try allocator.alloc(u8, region_buffer_size);
    defer allocator.free(region_buffer);
    @memset(region_buffer, 0);

    const vm_start: u64 = 0x4_0000_0000;

    var ctx: AccessViolationHandlerCtx = .{
        .tc = &tc,
        .allocator = allocator,
        .direct_mapping = false,
    };

    // Constant (read) access: record the violation, never grow.
    {
        var region = vm.memory.Region.init(
            .mutable,
            region_buffer[0..account_data_size],
            vm_start,
        );
        region.access_violation_handler_payload = 0;
        const old_end = region.vm_addr_end;
        tc.last_access_violation = null;

        AccessViolationHandlerCtx.handle(
            @ptrCast(&ctx),
            &region,
            region_buffer_size,
            .constant,
            vm_start + 50,
            100,
        );

        try std.testing.expectEqualDeep(
            sig.runtime.transaction_context.AccessViolationInfo{
                .access_type = .constant,
                .vm_addr = vm_start + 50,
                .len = 100,
            },
            tc.last_access_violation,
        );
        try std.testing.expectEqual(old_end, region.vm_addr_end);
        try std.testing.expectEqual(account_data_size, tc.accounts[0].account.data.len);
        try std.testing.expectEqual(@as(i64, 0), tc.accounts_resize_delta);
    }

    // Mutable access on a non-account region (payload == null): record only.
    {
        var region = vm.memory.Region.init(
            .mutable,
            region_buffer[0..account_data_size],
            vm_start,
        );
        const old_end = region.vm_addr_end;
        tc.last_access_violation = null;

        AccessViolationHandlerCtx.handle(
            @ptrCast(&ctx),
            &region,
            region_buffer_size,
            .mutable,
            vm_start + 150,
            10,
        );

        try std.testing.expect(tc.last_access_violation != null);
        try std.testing.expectEqual(old_end, region.vm_addr_end);
        try std.testing.expectEqual(account_data_size, tc.accounts[0].account.data.len);
        try std.testing.expectEqual(@as(i64, 0), tc.accounts_resize_delta);
    }

    // Access exceeds the account's reserved address space: record only.
    {
        var region = vm.memory.Region.init(
            .mutable,
            region_buffer[0..account_data_size],
            vm_start,
        );
        region.access_violation_handler_payload = 0;
        const old_end = region.vm_addr_end;
        tc.last_access_violation = null;

        AccessViolationHandlerCtx.handle(
            @ptrCast(&ctx),
            &region,
            150, // reserved
            .mutable,
            vm_start + 200,
            10,
        );

        try std.testing.expect(tc.last_access_violation != null);
        try std.testing.expectEqual(old_end, region.vm_addr_end);
        try std.testing.expectEqual(account_data_size, tc.accounts[0].account.data.len);
        try std.testing.expectEqual(@as(i64, 0), tc.accounts_resize_delta);
    }

    // Mutable access inside the current data length: record only (nothing to grow).
    {
        var region = vm.memory.Region.init(
            .mutable,
            region_buffer[0..account_data_size],
            vm_start,
        );
        region.access_violation_handler_payload = 0;
        const old_end = region.vm_addr_end;
        tc.last_access_violation = null;

        AccessViolationHandlerCtx.handle(
            @ptrCast(&ctx),
            &region,
            region_buffer_size,
            .mutable,
            vm_start + 50,
            10,
        );

        try std.testing.expect(tc.last_access_violation != null);
        try std.testing.expectEqual(old_end, region.vm_addr_end);
        try std.testing.expectEqual(account_data_size, tc.accounts[0].account.data.len);
        try std.testing.expectEqual(@as(i64, 0), tc.accounts_resize_delta);
    }

    // Non-direct-mapping grow path: account is resized, resize_delta accumulates,
    // and the region's host slice is extended in place into the pre-reserved pad.
    {
        var region = vm.memory.Region.init(
            .mutable,
            region_buffer[0..account_data_size],
            vm_start,
        );
        region.access_violation_handler_payload = 0;
        const original_buffer_ptr = region.host_memory.mutable.ptr;
        tc.last_access_violation = null;
        tc.accounts_resize_delta = 0;

        AccessViolationHandlerCtx.handle(
            @ptrCast(&ctx),
            &region,
            region_buffer_size,
            .mutable,
            vm_start + 150,
            10,
        );

        // new_len = min(reserved, min(MAX_DATA, old_len + remaining_growth))
        //         = min(region_buffer_size, min(MAX_DATA, ~20MiB)) = region_buffer_size.
        const expected_new_len: usize = region_buffer_size;

        try std.testing.expect(tc.last_access_violation != null);
        try std.testing.expectEqual(expected_new_len, tc.accounts[0].account.data.len);
        try std.testing.expectEqual(
            @as(i64, @intCast(expected_new_len - account_data_size)),
            tc.accounts_resize_delta,
        );
        try std.testing.expectEqual(vm_start + expected_new_len, region.vm_addr_end);
        try std.testing.expectEqual(expected_new_len, region.host_memory.mutable.len);
        // Non-direct-mapping must not move host_memory.ptr — the serialization
        // buffer it points into is what the VM sees, and moving it would
        // invalidate the VM's mapping.
        try std.testing.expectEqual(original_buffer_ptr, region.host_memory.mutable.ptr);
    }

    // Reset for next case.
    try tc.accounts[0].account.resize(allocator, account_data_size);
    tc.accounts_resize_delta = 0;

    // Resize budget exhausted: remaining_growth = 0 → new_len capped at old_len,
    // which doesn't cover the access → leave the region untouched.
    {
        var region = vm.memory.Region.init(
            .mutable,
            region_buffer[0..account_data_size],
            vm_start,
        );
        region.access_violation_handler_payload = 0;
        const old_end = region.vm_addr_end;
        tc.last_access_violation = null;
        tc.accounts_resize_delta =
            sig.runtime.program.system.MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION;

        AccessViolationHandlerCtx.handle(
            @ptrCast(&ctx),
            &region,
            region_buffer_size,
            .mutable,
            vm_start + 150,
            10,
        );

        try std.testing.expect(tc.last_access_violation != null);
        try std.testing.expectEqual(old_end, region.vm_addr_end);
        try std.testing.expectEqual(account_data_size, tc.accounts[0].account.data.len);
        // resize_delta must not be touched when no resize happens.
        try std.testing.expectEqual(
            sig.runtime.program.system.MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION,
            tc.accounts_resize_delta,
        );
    }

    // Direct-mapping grow path: region.host_memory is re-derived from
    // account.data (which may have moved due to the realloc).
    {
        tc.accounts_resize_delta = 0;
        ctx.direct_mapping = true;
        var region = vm.memory.Region.init(.mutable, tc.accounts[0].account.data, vm_start);
        region.access_violation_handler_payload = 0;
        tc.last_access_violation = null;

        AccessViolationHandlerCtx.handle(
            @ptrCast(&ctx),
            &region,
            region_buffer_size,
            .mutable,
            vm_start + 150,
            10,
        );

        try std.testing.expectEqual(
            tc.accounts[0].account.data.len,
            region.host_memory.mutable.len,
        );
        try std.testing.expectEqual(
            tc.accounts[0].account.data.ptr,
            region.host_memory.mutable.ptr,
        );
        try std.testing.expectEqual(
            vm_start + tc.accounts[0].account.data.len,
            region.vm_addr_end,
        );
    }
}

// SIMD-0460: covers `remapAccessViolation` — converts a generic
// `AccessViolation` (raised by the VM after the access-violation handler
// declined to grow) into the specific account-related `InstructionError` the
// bpf_loader reports. Each case sets `tc.last_access_violation` and asserts the
// returned error.
test remapAccessViolation {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_id = Pubkey.initRandom(prng.random());
    const data_account_key = Pubkey.initRandom(prng.random());

    const data_len: u64 = 100;
    const initial_data = try allocator.alloc(u8, data_len);
    defer allocator.free(initial_data);
    @memset(initial_data, 0xab);

    const cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{
            .{ .pubkey = data_account_key, .data = initial_data, .owner = program_id },
            .{ .pubkey = program_id, .owner = sig.runtime.ids.NATIVE_LOADER_ID },
        },
    });
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        testing.deinitAccountMap(cache, allocator);
    }

    var info = try testing.createInstructionInfo(
        &tc,
        program_id,
        @as([]const u8, &.{}),
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        },
    );
    defer info.deinit(allocator);

    try sig.runtime.executor.pushInstruction(&tc, info);
    const ic = try tc.getCurrentInstructionContext();

    const vm_data_addr: u64 = 0x4_0000_0000;
    const reserved_with_pad: u64 = data_len + bpf_serialize.MAX_PERMITTED_DATA_INCREASE;

    tc.serialized_accounts = .{};
    tc.serialized_accounts.appendAssumeCapacity(.{
        .vm_addr = vm_data_addr,
        .original_data_len = data_len,
        .vm_data_addr = vm_data_addr,
        .vm_key_addr = 0,
        .vm_lamports_addr = 0,
        .vm_owner_addr = 0,
    });

    // No recorded violation → no remap.
    tc.last_access_violation = null;
    try std.testing.expectEqual(
        @as(?InstructionError, null),
        remapAccessViolation(ic, false),
    );

    // Access falls outside every account region → no remap.
    tc.last_access_violation = .{
        .access_type = .mutable,
        .vm_addr = vm_data_addr + reserved_with_pad + 10,
        .len = 4,
    };
    try std.testing.expectEqual(
        @as(?InstructionError, null),
        remapAccessViolation(ic, false),
    );

    // Write within reserved range but past current data length, on a
    // writable+owned account → InvalidRealloc (the handler refused to grow).
    tc.last_access_violation = .{
        .access_type = .mutable,
        .vm_addr = vm_data_addr + data_len + 4,
        .len = 1,
    };
    try std.testing.expectEqual(
        @as(?InstructionError, InstructionError.InvalidRealloc),
        remapAccessViolation(ic, false),
    );

    // Write inside current data length, writable+owned → no remap
    // (AccessViolation in this region was not due to account semantics).
    tc.last_access_violation = .{
        .access_type = .mutable,
        .vm_addr = vm_data_addr + 4,
        .len = 1,
    };
    try std.testing.expectEqual(
        @as(?InstructionError, null),
        remapAccessViolation(ic, false),
    );

    // Read past readonly account data → AccountDataTooSmall.
    ic.ixn_info.account_metas.items[0].is_writable = false;
    tc.last_access_violation = .{
        .access_type = .constant,
        .vm_addr = vm_data_addr + data_len + 4,
        .len = 1,
    };
    try std.testing.expectEqual(
        @as(?InstructionError, InstructionError.AccountDataTooSmall),
        remapAccessViolation(ic, false),
    );

    // Write to a readonly account → ReadonlyDataModified.
    tc.last_access_violation = .{
        .access_type = .mutable,
        .vm_addr = vm_data_addr + 4,
        .len = 1,
    };
    try std.testing.expectEqual(
        @as(?InstructionError, InstructionError.ReadonlyDataModified),
        remapAccessViolation(ic, false),
    );
    ic.ixn_info.account_metas.items[0].is_writable = true;

    // Write to a writable account that isn't owned by the executing program
    // → ExternalAccountDataModified.
    const saved_owner = tc.accounts[0].account.owner;
    tc.accounts[0].account.owner = Pubkey.ZEROES;
    tc.last_access_violation = .{
        .access_type = .mutable,
        .vm_addr = vm_data_addr + 4,
        .len = 1,
    };
    try std.testing.expectEqual(
        @as(?InstructionError, InstructionError.ExternalAccountDataModified),
        remapAccessViolation(ic, false),
    );
    tc.accounts[0].account.owner = saved_owner;

    // Read past a writable account's data → InvalidRealloc (per SIMD-0460
    // a read that overshoots a writable account is also treated as a failed
    // grow attempt, not a "too small" condition).
    tc.last_access_violation = .{
        .access_type = .constant,
        .vm_addr = vm_data_addr + data_len + 4,
        .len = 1,
    };
    try std.testing.expectEqual(
        @as(?InstructionError, InstructionError.InvalidRealloc),
        remapAccessViolation(ic, false),
    );

    // Loader-v1 reserves no growth pad, so an access at vm_data_addr+data_len
    // falls *outside* the v1 reserved range and is not remapped — even though
    // the same access *would* be remapped under any other loader.
    tc.last_access_violation = .{
        .access_type = .mutable,
        .vm_addr = vm_data_addr + data_len,
        .len = 1,
    };
    try std.testing.expectEqual(
        @as(?InstructionError, null),
        remapAccessViolation(ic, true),
    );
    try std.testing.expectEqual(
        @as(?InstructionError, InstructionError.InvalidRealloc),
        remapAccessViolation(ic, false),
    );
}

test "remapAccessViolation ignores stale metadata from handled growth" {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_id = Pubkey.initRandom(prng.random());
    const account_data = [_]u8{ 1, 2, 3, 4 };
    const vm_data_addr = sig.vm.memory.INPUT_START + 0x80;

    const cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .owner = program_id,
                .data = &account_data,
            },
            .{
                .pubkey = program_id,
                .owner = ids.NATIVE_LOADER_ID,
            },
        },
    });
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        sig.runtime.testing.deinitAccountMap(cache, allocator);
    }

    var info = try testing.createInstructionInfo(
        &tc,
        program_id,
        &.{},
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
        },
    );
    defer info.deinit(allocator);

    try sig.runtime.executor.pushInstruction(&tc, info);
    const ic = try tc.getCurrentInstructionContext();

    tc.serialized_accounts.appendAssumeCapacity(.{
        .vm_addr = vm_data_addr,
        .original_data_len = account_data.len,
        .vm_data_addr = vm_data_addr,
        .vm_key_addr = 0,
        .vm_lamports_addr = 0,
        .vm_owner_addr = 0,
    });

    const initial_data = blk: {
        var account = try ic.borrowInstructionAccount(0);
        defer account.release();
        break :blk try allocator.dupe(u8, account.account.data);
    };
    defer allocator.free(initial_data);

    var region = vm.memory.Region.init(.mutable, initial_data, vm_data_addr).withPayload(0);
    var avh_ctx: AccessViolationHandlerCtx = .{
        .tc = &tc,
        .allocator = allocator,
        .direct_mapping = true,
    };

    AccessViolationHandlerCtx.handle(
        @ptrCast(&avh_ctx),
        &region,
        account_data.len + 4,
        .mutable,
        vm_data_addr + account_data.len,
        4,
    );

    {
        var account = try ic.borrowInstructionAccount(0);
        defer account.release();

        try std.testing.expectEqual(account_data.len + 4, account.constAccountData().len);
        try std.testing.expect(tc.last_access_violation != null);

        try account.setDataLength(allocator, &tc.accounts_resize_delta, account_data.len);
        try std.testing.expectEqual(account_data.len, account.constAccountData().len);
    }

    try std.testing.expectEqual(null, remapAccessViolation(ic, false));
}
