const std = @import("std");
const sig = @import("../../../sig.zig");

const ids = sig.runtime.ids;
const bincode = sig.bincode;
const executor = sig.runtime.executor;
const program = sig.runtime.program;
const pubkey_utils = sig.runtime.pubkey_utils;
const sysvar = sig.runtime.sysvar;
const system_program = sig.runtime.program.system_program;
const bpf_loader_program = sig.runtime.program.bpf_loader_program;

const Pubkey = sig.core.Pubkey;
const Instruction = sig.core.instruction.Instruction;
const InstructionError = sig.core.instruction.InstructionError;

const FeatureSet = sig.runtime.FeatureSet;
const InstructionContext = sig.runtime.InstructionContext;
const LogCollector = sig.runtime.LogCollector;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    var program_account = try ic.borrowProgramAccount();

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L408
    if (ids.NATIVE_LOADER_ID.equals(&program_account.account.owner)) {
        program_account.release();
        if (bpf_loader_program.v1.ID.equals(&ic.info.program_meta.pubkey)) {
            try ic.tc.consumeCompute(bpf_loader_program.v1.COMPUTE_UNITS);
            try ic.tc.log("Deprecated loader is no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_program.v2.ID.equals(&ic.info.program_meta.pubkey)) {
            try ic.tc.consumeCompute(bpf_loader_program.v2.COMPUTE_UNITS);
            try ic.tc.log("BPF loader management instructions are no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_program.v3.ID.equals(&ic.info.program_meta.pubkey)) {
            try ic.tc.consumeCompute(bpf_loader_program.v3.COMPUTE_UNITS);
            return executeBpfLoaderV3ProgramInstruction(allocator, ic);
        } else {
            return InstructionError.IncorrectProgramId;
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L434
    if (!program_account.account.executable) {
        try ic.tc.log("Program is not executable", .{});
        return InstructionError.IncorrectProgramId;
    }
}

pub fn executeBpfLoaderV3ProgramInstruction(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L477
    const instruction = try ic.info.deserializeInstruction(allocator, bpf_loader_program.v3.Instruction);
    defer sig.bincode.free(allocator, instruction);

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

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L479-L495
pub fn executeV3InitializeBuffer(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    try ic.info.checkNumberOfAccounts(2);

    const buffer_account_index = 0;
    const buffer_authority_index = 1;

    var buffer_account = try ic.borrowInstructionAccount(buffer_account_index);
    defer buffer_account.release();
    const buffer_account_state = try buffer_account.deserializeFromAccountData(
        allocator,
        bpf_loader_program.v3.State,
    );

    if (buffer_account_state != bpf_loader_program.v3.State.uninitialized) {
        try ic.tc.log("Buffer account already initialized", .{});
        return InstructionError.AccountAlreadyInitialized;
    }

    try buffer_account.serializeIntoAccountData(bpf_loader_program.v3.State{
        .buffer = .{
            .authority_address = ic.info.account_metas.buffer[buffer_authority_index].pubkey,
        },
    });
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L496-L526
pub fn executeV3Write(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    offset: u32,
    bytes: []const u8,
) (error{OutOfMemory} || InstructionError)!void {
    try ic.info.checkNumberOfAccounts(2);

    const buffer_account_index = 0;
    const buffer_authority_index = 1;

    var buffer_account = try ic.borrowInstructionAccount(buffer_account_index);
    defer buffer_account.release();

    switch (try buffer_account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
        .buffer => |state| {
            if (state.authority_address) |buffer_authority| {
                if (!buffer_authority.equals(&ic.info.account_metas.buffer[buffer_authority_index].pubkey)) {
                    try ic.tc.log("Incorrect buffer authority provided", .{});
                    return InstructionError.IncorrectAuthority;
                }

                if (!try ic.info.isIndexSigner(buffer_authority_index)) {
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

    if (buffer_account.checkDataIsMutable()) |err| return err;

    const start = bpf_loader_program.v3.State.BUFFER_METADATA_SIZE + @as(usize, offset);
    const end = start +| bytes.len;

    if (end > buffer_account.constAccountData().len) {
        try ic.tc.log("Write overflow: {} < {}", .{ bytes.len, end });
        return InstructionError.AccountDataTooSmall;
    }

    @memcpy(buffer_account.account.data[start..end], bytes);
}

/// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L565-L738
pub fn executeV3DeployWithMaxDataLen(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    max_data_len: u64,
) (error{OutOfMemory} || InstructionError)!void {
    const payer_index = 0;
    const program_data_index = 1;
    const program_index = 2;
    const buffer_index = 3;
    const rent_index = 4;
    const clock_index = 5;
    // const system_program_index = 6;
    const authority_index = 7;

    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L565
    try ic.info.checkNumberOfAccounts(4);

    // Safety: at least 4 accounts are present
    const payer_key = ic.info.account_metas.buffer[payer_index].pubkey;
    const program_data_key = ic.info.account_metas.buffer[program_data_index].pubkey;

    const rent = try ic.getSysvarWithAccountCheck(sysvar.Rent, rent_index);
    const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, clock_index);

    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L575
    try ic.info.checkNumberOfAccounts(8);

    // Safety: at least 8 accounts are present
    const authority_key = ic.info.account_metas.buffer[authority_index].pubkey;

    // Verify program account and retrieve its program id
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L582-L597
    const new_program_id = blk: {
        const program_account = try ic.borrowInstructionAccount(program_index);
        defer program_account.release();

        const program_state = try program_account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State);

        if (program_state != bpf_loader_program.v3.State.uninitialized) {
            try ic.tc.log("Program account already initialized", .{});
            return InstructionError.AccountAlreadyInitialized;
        }

        if (program_account.constAccountData().len < bpf_loader_program.v3.State.PROGRAM_SIZE) {
            try ic.tc.log("Program account too small", .{});
            return InstructionError.AccountDataTooSmall;
        }

        if (program_account.account.lamports < rent.minimumBalance(program_account.constAccountData().len)) {
            try ic.tc.log("Program account not rent-exempt", .{});
            return InstructionError.ExecutableAccountNotRentExempt;
        }

        break :blk program_account.pubkey;
    };

    // Verify buffer account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L601-L638
    const program_data_len = bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE +| max_data_len;
    {
        const buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();

        switch (try buffer_account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
            .buffer => |state| {
                if (state.authority_address == null or !state.authority_address.?.equals(&authority_key)) {
                    try ic.tc.log("Buffer and upgrade authority don't match", .{});
                    return InstructionError.IncorrectAuthority;
                }

                // Safety: at least 8 accounts are present
                if (!ic.info.account_metas.buffer[authority_index].is_signer) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            },
            else => {
                try ic.tc.log("Invalid Buffer account", .{});
                return InstructionError.InvalidArgument;
            },
        }

        if (buffer_account.constAccountData().len <= bpf_loader_program.v3.State.BUFFER_METADATA_SIZE) {
            try ic.tc.log("Buffer account too small", .{});
            return InstructionError.AccountDataTooSmall;
        }

        const buffer_data_len = buffer_account.constAccountData().len -| bpf_loader_program.v3.State.BUFFER_METADATA_SIZE;

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
        ic.tc.custom_error = 12345; // TODO: Correct error behaviour here?
        return InstructionError.Custom;
    };

    if (!derived_key.equals(&program_data_key)) {
        try ic.tc.log("ProgramData address is not derived", .{});
        return InstructionError.InvalidArgument;
    }

    // Drain the Buffer account to payer before paying for program data account
    {
        var buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();

        var payer_account = try ic.borrowInstructionAccount(payer_index);
        defer payer_account.release();

        try payer_account.addLamports(buffer_account.account.lamports);
        try buffer_account.setLamports(0);
    }

    // Create the ProgramData account
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L658-L680
    const signer_derived_key = pubkey_utils.createProgramAddress(
        &.{&new_program_id.data},
        &.{bump_seed},
        ic.info.program_meta.pubkey,
    ) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return InstructionError.Custom;
    };

    const account_metas = &.{
        .{ .pubkey = payer_key, .is_signer = true, .is_writable = true },
        .{ .pubkey = program_data_key, .is_signer = true, .is_writable = true },
        // pass an extra account to avoid the overly strict UnbalancedInstruction error
        // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L668-L669
        .{ .pubkey = ic.info.account_metas.buffer[buffer_index].pubkey, .is_signer = false, .is_writable = true },
    };

    const data = bincode.writeAlloc(
        allocator,
        system_program.Instruction{
            .create_account = .{
                .lamports = @max(1, rent.minimumBalance(program_data_len)),
                .space = program_data_len,
                .owner = ic.info.program_meta.pubkey,
            },
        },
        .{},
    ) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return InstructionError.Custom;
    };
    defer allocator.free(data);

    try executor.executeNativeCpiInstruction(
        allocator,
        ic.tc,
        Instruction{
            .program_id = system_program.ID,
            .accounts = account_metas,
            .data = data,
        },
        &.{signer_derived_key},
    );

    // Load and verify the program bits and deploy the program
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L683-L698
    {
        const buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();

        if (buffer_account.constAccountData().len < bpf_loader_program.v3.State.BUFFER_METADATA_SIZE)
            return InstructionError.AccountDataTooSmall;

        try deployProgram(
            allocator,
            new_program_id,
            ic.info.program_meta.pubkey,
            bpf_loader_program.v3.State.PROGRAM_SIZE +| program_data_len,
            buffer_account.constAccountData()[bpf_loader_program.v3.State.BUFFER_METADATA_SIZE..],
            clock.slot,
            ic.tc.feature_set,
            if (ic.tc.log_collector != null) &ic.tc.log_collector.? else null,
        );
    }

    // Update the PorgramData account and record the program bits
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L704-L726
    {
        var program_data_account = try ic.borrowInstructionAccount(program_data_index);
        defer program_data_account.release();
        try program_data_account.serializeIntoAccountData(bpf_loader_program.v3.State{ .program_data = .{
            .slot = clock.slot,
            .upgrade_authority_address = authority_key,
        } });
        const program_data = try program_data_account.mutableAccountData();

        var buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();

        @memcpy(program_data.ptr, buffer_account.constAccountData());

        try buffer_account.setDataLength(allocator, &ic.tc.accounts_resize_delta, bpf_loader_program.v3.State.BUFFER_METADATA_SIZE);
    }

    // Update the program account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L729-735
    {
        var program_account = try ic.borrowInstructionAccount(program_index);
        defer program_account.release();
        try program_account.serializeIntoAccountData(bpf_loader_program.v3.State{ .program = .{
            .programdata_address = program_data_key,
        } });
        // TODO: Is it okay to pass rent here which is loaded from the sysvar_cache rather than the rent stored in the
        // transaction context in agave?
        try program_account.setExecutable(true, rent);
    }

    try ic.tc.log("Deployed program {}", .{new_program_id});
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L705-L894
pub fn executeV3Upgrade(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    try ic.info.checkNumberOfAccounts(3);

    const programdata_key = ic.info.getAccountMetaAtIndex(0).?.pubkey;
    const rent = try ic.getSysvarWithAccountCheck(sysvar.Rent, 4);
    const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 5);
    try ic.info.checkNumberOfAccounts(7);
    const authority_key = ic.info.getAccountMetaAtIndex(6).?.pubkey;

    // verify program

    const new_program_id = blk: {
        const program_account = try ic.borrowInstructionAccount(1);
        defer program_account.release();

        if (!program_account.account.executable) {
            try ic.tc.log("Program account not executable", .{});
            return InstructionError.AccountNotExecutable;
        }
        if (!program_account.context.is_writable) {
            try ic.tc.log("Program account not writeable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!program_account.account.owner.equals(&program_account.context.program_id)) { // TODO: get_owner() != program_id
            try ic.tc.log("Program account not owned by loader", .{});
            return InstructionError.IncorrectProgramId;
        }
        switch (try program_account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
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
        const buffer = try ic.borrowInstructionAccount(2);
        defer buffer.release();

        switch (try buffer.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
            .buffer => |data| {
                if (data.authority_address == null or !data.authority_address.?.equals(&authority_key)) {
                    try ic.tc.log("Buffer and upgrade authority don't match", .{});
                    return InstructionError.IncorrectAuthority;
                }
                if (!(try ic.info.isIndexSigner(6))) {
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
            .data_offset = bpf_loader_program.v3.State.BUFFER_METADATA_SIZE,
            .data_len = buffer.constAccountData().len -| bpf_loader_program.v3.State.BUFFER_METADATA_SIZE,
        };
        if (buffer.constAccountData().len < buf.data_offset or buf.data_len == 0) {
            try ic.tc.log("Buffer account too small", .{});
            return InstructionError.InvalidAccountData;
        }
        break :blk buf;
    };

    // Verify ProgramData account

    const progdata = blk: {
        const programdata = try ic.borrowInstructionAccount(0);
        defer programdata.release();

        const offset = bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE;
        const balance_required = @max(1, rent.minimumBalance(programdata.constAccountData().len));

        if (programdata.constAccountData().len < bpf_loader_program.v3.State.sizeOfProgramData(buf.data_len)) {
            try ic.tc.log("ProgramData account not large enough", .{});
            return InstructionError.AccountDataTooSmall;
        }
        if (programdata.account.lamports +| buf.lamports < balance_required) {
            try ic.tc.log("Buffer account balance too low to fund upgrade", .{});
            return InstructionError.InsufficientFunds;
        }

        switch (try programdata.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
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
                if (!(try ic.info.isIndexSigner(6))) {
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
        const buffer = try ic.borrowInstructionAccount(2);
        defer buffer.release();

        if (buffer.constAccountData().len < buf.data_offset) {
            return InstructionError.AccountDataTooSmall;
        }

        try deployProgram(
            allocator,
            new_program_id,
            ic.info.program_meta.pubkey,
            bpf_loader_program.v3.State.PROGRAM_SIZE +| progdata.len,
            buffer.constAccountData()[buf.data_offset..],
            clock.slot,
            ic.tc.feature_set,
            if (ic.tc.log_collector != null) &ic.tc.log_collector.? else null,
        );
    }

    // Update the ProgramData account, record the upgraded data, and zero the rest:

    var programdata = try ic.borrowInstructionAccount(0);
    defer programdata.release();

    {
        try programdata.serializeIntoAccountData(bpf_loader_program.v3.State{ .program_data = .{
            .slot = clock.slot,
            .upgrade_authority_address = authority_key,
        } });

        const dst_slice = try programdata.mutableAccountData();
        if (dst_slice.len < progdata.offset +| buf.data_len) {
            return InstructionError.AccountDataTooSmall;
        }

        const buffer = try ic.borrowInstructionAccount(2);
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

    try spill.addLamports(programdata.account.lamports +| buf.lamports -| progdata.balance_required);
    try buffer.setLamports(0);
    try programdata.setLamports(progdata.balance_required);
    try buffer.setDataLength(allocator, &ic.tc.accounts_resize_delta, bpf_loader_program.v3.State.sizeOfBuffer(0));

    try ic.tc.log("Upgraded program {any}", .{new_program_id});
}

/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/programs/bpf_loader/src/lib.rs#L946-L1010
pub fn executeV3SetAuthority(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    try ic.info.checkNumberOfAccounts(2);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    const present_authority_key = ic.info.getAccountMetaAtIndex(1).?.pubkey;
    const new_authority = if (ic.info.getAccountMetaAtIndex(2)) |meta| meta.pubkey else null;

    switch (try account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
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
            if (!(try ic.info.isIndexSigner(1))) {
                try ic.tc.log("Buffer authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(bpf_loader_program.v3.State{
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
            if (!(try ic.info.isIndexSigner(1))) {
                try ic.tc.log("Upgrade authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(bpf_loader_program.v3.State{
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

    try ic.tc.log("New authority {?}", .{new_authority});
}

/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/programs/bpf_loader/src/lib.rs#L1011-L1083
pub fn executeV3SetAuthorityChecked(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    if (!ic.tc.feature_set.active.contains(FeatureSet.enable_bpf_loader_set_authority_checked_ix)) {
        return InstructionError.InvalidInstructionData;
    }

    try ic.info.checkNumberOfAccounts(3);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    const present_authority_key = ic.info.getAccountMetaAtIndex(1).?.pubkey;
    const new_authority = ic.info.getAccountMetaAtIndex(2).?.pubkey;

    switch (try account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
        .buffer => |buffer| {
            if (buffer.authority_address == null) {
                try ic.tc.log("Buffer is immutable", .{});
                return InstructionError.Immutable;
            }
            if (!buffer.authority_address.?.equals(&present_authority_key)) {
                try ic.tc.log("Incorrect buffer authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!(try ic.info.isIndexSigner(1))) {
                try ic.tc.log("Buffer authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            if (!(try ic.info.isIndexSigner(2))) {
                try ic.tc.log("New authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(bpf_loader_program.v3.State{
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
            if (!(try ic.info.isIndexSigner(1))) {
                try ic.tc.log("Upgrade authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            if (!(try ic.info.isIndexSigner(2))) {
                try ic.tc.log("New authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(bpf_loader_program.v3.State{
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

    try ic.tc.log("New authority {?}", .{new_authority});
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L1033-L1138
pub fn executeV3Close(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    try ic.info.checkNumberOfAccounts(2);
    if (ic.info.getAccountMetaAtIndex(0).?.index_in_transaction ==
        ic.info.getAccountMetaAtIndex(1).?.index_in_transaction)
    {
        try ic.tc.log("Recipient is the same as the account being closed", .{});
        return InstructionError.InvalidArgument;
    }

    var close_account = try ic.borrowInstructionAccount(0);
    var close_account_released = false; // NOTE: used to simulate drop(close_account) below.
    defer if (!close_account_released) close_account.release();

    const close_key = close_account.pubkey;
    const close_account_state = try close_account.deserializeFromAccountData(
        allocator,
        bpf_loader_program.v3.State,
    );
    try close_account.setDataLength(allocator, &ic.tc.accounts_resize_delta, bpf_loader_program.v3.State.UNINITIALIZED_SIZE);
    switch (close_account_state) {
        .uninitialized => {
            var recipient_account = try ic.borrowInstructionAccount(1);
            defer recipient_account.release();

            try recipient_account.addLamports(close_account.account.lamports);
            try close_account.setLamports(0);
            try ic.tc.log("Closed Uninitialized {any}", .{close_key});
        },
        .buffer => |data| {
            try ic.info.checkNumberOfAccounts(3);
            close_account.release();
            close_account_released = true;

            try commonCloseAccount(ic, data.authority_address);
            try ic.tc.log("Closed Buffer {any}", .{close_key});
        },
        .program_data => |data| {
            try ic.info.checkNumberOfAccounts(4);
            close_account.release();
            close_account_released = true;

            var program_account = try ic.borrowInstructionAccount(3); // NOTE: named program, but inst?
            var program_account_released = false; // NOTE: used to simulate drop(program_account) below.
            defer if (!program_account_released) program_account.release();

            const program_key = program_account.pubkey;
            const authority_address = data.upgrade_authority_address;

            if (!program_account.context.is_writable) {
                try ic.tc.log("Program account is not writable", .{});
                return InstructionError.InvalidArgument;
            }
            if (!program_account.account.owner.equals(&program_account.context.program_id)) { // NOTE: getOwner() == ic.getLastProgramKey()
                try ic.tc.log("Program account is not owned by the loader", .{});
                return InstructionError.IncorrectProgramId;
            }

            var clock = ic.tc.sysvar_cache.get(sysvar.Clock) orelse return InstructionError.UnsupportedSysvar;
            if (clock.slot == data.slot) {
                try ic.tc.log("Program was deployed in this block already", .{});
                return InstructionError.InvalidArgument;
            }

            switch (try program_account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
                .program => |program_data| {
                    if (!program_data.programdata_address.equals(&close_key)) {
                        try ic.tc.log("PRogramData account does not match ProgramData account", .{});
                        return InstructionError.InvalidArgument;
                    }

                    program_account.release();
                    program_account_released = true;
                    try commonCloseAccount(ic, authority_address);

                    clock = ic.tc.sysvar_cache.get(sysvar.Clock) orelse return InstructionError.UnsupportedSysvar;
                    // TODO: This depends on program cache which isn't implemented yet.
                    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L1114-L1123
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
) !void {
    if (authority_address == null) {
        try ic.tc.log("Account is immutable", .{});
        return InstructionError.Immutable;
    }

    const auth_account = ic.info.getAccountMetaAtIndex(2) orelse return InstructionError.MissingAccount;
    if (!authority_address.?.equals(&auth_account.pubkey)) {
        try ic.tc.log("Incorrect authority provided", .{});
        return InstructionError.IncorrectAuthority;
    }
    if (!(try ic.info.isIndexSigner(2))) {
        try ic.tc.log("Authority did not sign", .{});
        return InstructionError.MissingRequiredSignature;
    }

    var close_account = try ic.borrowInstructionAccount(0);
    defer close_account.release();

    var recipient_account = try ic.borrowInstructionAccount(1);
    defer recipient_account.release();

    try recipient_account.addLamports(close_account.account.lamports);
    try close_account.setLamports(0);
    try close_account.serializeIntoAccountData(bpf_loader_program.v3.State{ .uninitialized = {} });
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L1139-L1296
pub fn executeV3ExtendProgram(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    additional_bytes: u32,
) !void {
    if (additional_bytes == 0) {
        try ic.tc.log("Additional bytes must be greater than 0", .{});
        return InstructionError.InvalidInstructionData;
    }

    const program_data_account_index = 0;
    const program_account_index = 1;
    // System program is only required when a CPI is performed
    const optional_system_program_account_index = 2;
    _ = &optional_system_program_account_index; // allow(unused)
    const optional_payer_account_index = 3;

    var programdata = try ic.borrowInstructionAccount(program_data_account_index);
    var programdata_released = false; // simulate drop(program_data) down below.
    defer if (!programdata_released) programdata.release();

    const programdata_key = programdata.pubkey;
    if (!programdata.account.owner.equals(&programdata.context.program_id)) {
        try ic.tc.log("ProgramData owner is invalid", .{});
        return InstructionError.InvalidAccountOwner;
    }
    if (!programdata.context.is_writable) {
        try ic.tc.log("ProgramData owner is invalid", .{});
        return InstructionError.InvalidArgument;
    }

    const program_key = blk: {
        var program_account = try ic.borrowInstructionAccount(program_account_index);
        defer program_account.release();

        if (!program_account.context.is_writable) {
            try ic.tc.log("Program account is not writeable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!program_account.account.owner.equals(&program_account.context.program_id)) {
            try ic.tc.log("Program account not owned by loader", .{});
            return InstructionError.InvalidAccountOwner;
        }

        switch (try program_account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
            .program => |data| {
                if (!data.programdata_address.equals(&programdata_key)) {
                    try ic.tc.log("Program account does not match ProgramData account", .{});
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

    // [agave] https://github.com/anza-xyz/agave/blob/5fa721b3b27c7ba33e5b0e1c55326241bb403bb1/program-runtime/src/sysvar_cache.rs#L130-L141
    const clock = ic.tc.sysvar_cache.get(sysvar.Clock) orelse return InstructionError.UnsupportedSysvar;

    const upgrade_authority_address =
        switch (try programdata.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
        .program_data => |data| blk: {
            if (clock.slot == data.slot) {
                try ic.tc.log("Program was extended in this block already", .{});
                return InstructionError.InvalidArgument;
            }
            if (data.upgrade_authority_address == null) {
                try ic.tc.log("Cannot extend ProgramData accounts that are not upgradeable", .{});
                return InstructionError.Immutable;
            }
            break :blk data.upgrade_authority_address;
        },
        else => {
            try ic.tc.log("ProgramData state is invalid", .{});
            return InstructionError.InvalidAccountData;
        },
    };

    const required_payment = blk: {
        const balance = programdata.account.lamports;
        // [agave] https://github.com/anza-xyz/agave/blob/5fa721b3b27c7ba33e5b0e1c55326241bb403bb1/program-runtime/src/sysvar_cache.rs#L130-L141
        const rent = ic.tc.sysvar_cache.get(sysvar.Rent) orelse return InstructionError.UnsupportedSysvar;
        const min_balance = @max(1, rent.minimumBalance(new_len));
        break :blk min_balance -| balance;
    };

    // Borrowed accounts need to be dropped before native_invoke
    programdata.release();
    programdata_released = true;

    // Determine the program ID to prevent overlapping mutable/immutable borrow of invoke context.
    if (required_payment > 0) {
        // [agave] https://github.com/anza-xyz/agave/blob/ad0983afd4efa711cf2258aa9630416ed6716d2a/transaction-context/src/lib.rs#L260-L267
        const payer = ic.info.getAccountMetaAtIndex(optional_payer_account_index) orelse return InstructionError.NotEnoughAccountKeys;

        const data = bincode.writeAlloc(
            allocator,
            system_program.Instruction{
                .transfer = .{ .lamports = required_payment },
            },
            .{},
        ) catch |err| {
            ic.tc.custom_error = @intFromError(err);
            return InstructionError.Custom;
        };
        defer allocator.free(data);

        try executor.executeNativeCpiInstruction(
            allocator,
            ic.tc,
            Instruction{
                .program_id = system_program.ID,
                .accounts = &.{
                    .{ .pubkey = payer.pubkey, .is_signer = true, .is_writable = true },
                    .{ .pubkey = programdata_key, .is_signer = false, .is_writable = true },
                },
                .data = data,
            },
            &.{},
        );
    }

    {
        programdata = try ic.borrowInstructionAccount(program_data_account_index);
        defer programdata.release();

        try programdata.setDataLength(allocator, &ic.tc.accounts_resize_delta, new_len);

        try deployProgram(
            allocator,
            program_key,
            ic.info.program_meta.pubkey,
            bpf_loader_program.v3.State.PROGRAM_SIZE +| new_len,
            programdata.constAccountData()[bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE..],
            clock.slot,
            ic.tc.feature_set,
            if (ic.tc.log_collector != null) &ic.tc.log_collector.? else null,
        );
    }

    programdata = try ic.borrowInstructionAccount(program_data_account_index);
    defer programdata.release();

    try programdata.serializeIntoAccountData(bpf_loader_program.v3.State{
        .program_data = .{
            .slot = clock.slot,
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
    program_id: Pubkey,
    owner_id: Pubkey,
    program_len: usize,
    program_data: []const u8,
    slot: u64,
    feature_set: FeatureSet,
    maybe_log_collector: ?*LogCollector,
) (error{OutOfMemory} || InstructionError)!void {
    _ = allocator;
    _ = program_id;
    _ = owner_id;
    _ = program_len;
    _ = program_data;
    _ = slot;
    _ = feature_set;
    _ = maybe_log_collector;
}

test "executeV3InitializeBuffer" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_state = bpf_loader_program.v3.State.uninitialized;
    const initial_buffer_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_state = bpf_loader_program.v3.State{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const final_buffer_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(final_buffer_account_data);
    @memset(final_buffer_account_data, 0);
    _ = try bincode.writeToSlice(final_buffer_account_data, final_buffer_account_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        bpf_loader_program.v3,
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
    );
}

test "executeV3Write" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const offset = 10;
    const source = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

    const initial_buffer_account_state = bpf_loader_program.v3.State{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const initial_buffer_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State) + offset + source.len);
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    const start = bpf_loader_program.v3.State.BUFFER_METADATA_SIZE + offset;
    const end = start +| source.len;
    @memcpy(final_buffer_account_data[start..end], &source);

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        bpf_loader_program.v3,
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
    );
}

test "executeDeployWithMaxDataLen" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    const payer_account_key = Pubkey.initRandom(prng.random());
    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key = try pubkey_utils.createProgramAddress(
        &.{&program_account_key.data},
        &.{255},
        bpf_loader_program.v3.ID,
    );
    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const rent = sysvar.Rent.DEFAULT;

    const max_data_len = 1024;

    const initial_program_account_data = try allocator.alloc(u8, bpf_loader_program.v3.State.PROGRAM_SIZE);
    defer allocator.free(initial_program_account_data);
    @memset(initial_program_account_data, 0);
    _ = try bincode.writeToSlice(initial_program_account_data, bpf_loader_program.v3.State.uninitialized, .{});
    const initial_program_account_lamports = rent.minimumBalance(initial_program_account_data.len);

    const final_program_account_data = try allocator.alloc(u8, bpf_loader_program.v3.State.PROGRAM_SIZE);
    defer allocator.free(final_program_account_data);
    @memset(final_program_account_data, 0);
    _ = try bincode.writeToSlice(final_program_account_data, bpf_loader_program.v3.State{ .program = .{
        .programdata_address = program_data_account_key,
    } }, .{});

    const initial_buffer_account_data = try allocator.alloc(u8, max_data_len);
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, bpf_loader_program.v3.State{ .buffer = .{ .authority_address = buffer_authority_key } }, .{});
    const initial_buffer_account_lamports = 1_000;
    const final_buffer_account_data = initial_buffer_account_data[0..bpf_loader_program.v3.State.BUFFER_METADATA_SIZE];

    const final_program_data_account_size = bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE +| max_data_len;
    const final_program_data_account_data = try allocator.alloc(u8, final_program_data_account_size);
    defer allocator.free(final_program_data_account_data);
    @memset(final_program_data_account_data, 0);
    _ = try bincode.writeToSlice(final_program_data_account_data, bpf_loader_program.v3.State{ .buffer = .{ .authority_address = buffer_authority_key } }, .{});
    // TODO: set buffer account data to random bytes and set as final program account data

    const log_collector = sig.runtime.LogCollector.default(allocator);
    defer log_collector.deinit();

    testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3,
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
                    .lamports = @max(1, rent.minimumBalance(final_program_data_account_size)),
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
                    .pubkey = program.system_program.ID,
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
                .rent = sysvar.Rent.DEFAULT,
                .clock = sysvar.Clock.DEFAULT,
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS + 150, // TODO: Should we need extra for system program cpi???
            .log_collector = log_collector,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = payer_account_key,
                    .lamports = initial_buffer_account_lamports,
                },
                .{
                    .pubkey = program_data_account_key,
                    .lamports = @max(1, rent.minimumBalance(final_program_data_account_size)),
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
                    .pubkey = program.system_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                    .executable = true,
                },
                .{ .pubkey = buffer_authority_key },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .accounts_resize_delta = @intCast(final_buffer_account_data.len + bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE +| max_data_len -| initial_buffer_account_data.len),
            .sysvar_cache = .{
                .rent = sysvar.Rent.DEFAULT,
                .clock = sysvar.Clock.DEFAULT,
            },
        },
    ) catch |err| {
        for (log_collector.collect()) |msg| {
            std.debug.print("{any}\n", .{msg});
        }
        return err;
    };
}

test "executeV3SetAuthority" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());
    const new_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(initial_buffer_account_data);
    _ = try bincode.writeToSlice(
        initial_buffer_account_data,
        bpf_loader_program.v3.State{
            .buffer = .{ .authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    _ = try bincode.writeToSlice(
        final_buffer_account_data,
        bpf_loader_program.v3.State{
            .buffer = .{ .authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.buffer
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3,
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
    );

    const initial_program_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(initial_program_account_data);
    _ = try bincode.writeToSlice(
        initial_program_account_data,
        bpf_loader_program.v3.State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_program_account_data = try allocator.dupe(u8, initial_program_account_data);
    defer allocator.free(final_program_account_data);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        bpf_loader_program.v3.State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.program_data
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3,
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
    );
}

test "executeV3SetAuthorityChecked" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());
    const new_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(initial_buffer_account_data);
    _ = try bincode.writeToSlice(
        initial_buffer_account_data,
        bpf_loader_program.v3.State{
            .buffer = .{ .authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    _ = try bincode.writeToSlice(
        final_buffer_account_data,
        bpf_loader_program.v3.State{
            .buffer = .{ .authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.buffer (1 and 2 must be signers).
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3,
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
                .{ .pubkey = FeatureSet.enable_bpf_loader_set_authority_checked_ix, .slot = 0 },
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
    );

    const initial_program_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(initial_program_account_data);
    _ = try bincode.writeToSlice(
        initial_program_account_data,
        bpf_loader_program.v3.State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_program_account_data = try allocator.dupe(u8, initial_program_account_data);
    defer allocator.free(final_program_account_data);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        bpf_loader_program.v3.State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.program_data (1 and 2 must be signers).
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3,
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
                    .pubkey = bpf_loader_program.v3.ID, // id of program u wanna run
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID, // bpf_loader_program.v3.ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            .feature_set = &.{
                .{ .pubkey = FeatureSet.enable_bpf_loader_set_authority_checked_ix, .slot = 0 },
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
    );
}

test "executeV3Close" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_recipient_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const initial_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(initial_account_data);
    const final_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(final_account_data);

    const num_lamports = 42 + prng.random().uintAtMost(u64, 1337);

    // uninitialized
    {
        const uninitialized_data = try bincode.writeToSlice(
            initial_account_data,
            bpf_loader_program.v3.State{ .uninitialized = {} },
            .{},
        );

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3,
            bpf_loader_program.v3.Instruction{
                .close = {},
            },
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = buffer_account_key,
                        .data = uninitialized_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = buffer_recipient_key,
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
                        .data = uninitialized_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = buffer_recipient_key,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
            },
        );
    }

    // buffer
    {
        const initial_data = try bincode.writeToSlice(
            initial_account_data,
            bpf_loader_program.v3.State{ .buffer = .{ .authority_address = buffer_authority_key } },
            .{},
        );

        const final_data = try bincode.writeToSlice(
            final_account_data,
            bpf_loader_program.v3.State{ .uninitialized = {} },
            .{},
        );

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3,
            bpf_loader_program.v3.Instruction{
                .close = {},
            },
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = buffer_account_key,
                        .data = initial_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = buffer_recipient_key,
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
                        .data = final_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = buffer_recipient_key,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = buffer_authority_key,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .accounts_resize_delta = -@as(i64, @intCast(initial_data.len - final_data.len)),
            },
        );
    }
}

test "executeV3Upgrade" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const spill_account_key = Pubkey.initRandom(prng.random());
    const upgrade_authority_key = Pubkey.initRandom(prng.random());
    const buffer_account_key = Pubkey.initRandom(prng.random());

    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key = try pubkey_utils.createProgramAddress(
        &.{&program_account_key.data},
        &.{255},
        bpf_loader_program.v3.ID,
    );

    const rent = sysvar.Rent.DEFAULT;
    var clock = sysvar.Clock.DEFAULT;
    clock.slot += 1337;

    const buffer_size = 512;

    const program_data_buffer = try allocator.alloc(u8, bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE + buffer_size);
    defer allocator.free(program_data_buffer);
    _ = try bincode.writeToSlice(
        program_data_buffer,
        bpf_loader_program.v3.State{
            .program_data = .{
                .slot = clock.slot - 1, // must be before the current clock's slot.
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        .{},
    );

    const updated_program_data_buffer = try allocator.alloc(u8, program_data_buffer.len);
    defer allocator.free(updated_program_data_buffer);
    _ = try bincode.writeToSlice(
        updated_program_data_buffer,
        bpf_loader_program.v3.State{ .program_data = .{
            .slot = clock.slot,
            .upgrade_authority_address = upgrade_authority_key,
        } },
        .{},
    );

    const program_account_buffer = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(program_account_buffer);
    _ = try bincode.writeToSlice(
        program_account_buffer,
        bpf_loader_program.v3.State{ .program = .{ .programdata_address = program_data_account_key } },
        .{},
    );

    const buffer_account_data = try allocator.alloc(u8, bpf_loader_program.v3.State.BUFFER_METADATA_SIZE + buffer_size);
    defer allocator.free(buffer_account_data);
    _ = try bincode.writeToSlice(
        buffer_account_data,
        bpf_loader_program.v3.State{ .buffer = .{ .authority_address = upgrade_authority_key } },
        .{},
    );

    const buffer_aid_balance = 42;
    const spill_balance = 100;
    const buffer_balance = rent.minimumBalance(buffer_account_data.len) + buffer_aid_balance;
    const program_data_balance = rent.minimumBalance(program_data_buffer.len) - buffer_aid_balance;

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3,
        bpf_loader_program.v3.Instruction{
            .upgrade = {},
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 }, // programdata
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 }, // program
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 2 }, // buffer written account
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 3 }, // spill account
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 }, // sysvar rent
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 5 }, // sysvar clock
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 6 }, // upgrade account
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_data_account_key,
                    .data = program_data_buffer,
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
                    .data = updated_program_data_buffer,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = rent.minimumBalance(program_data_buffer.len),
                },
                .{
                    .pubkey = program_account_key,
                    .data = program_account_buffer,
                    .owner = bpf_loader_program.v3.ID,
                    .executable = true,
                },
                .{
                    .pubkey = buffer_account_key,
                    .data = buffer_account_data[0..bpf_loader_program.v3.State.BUFFER_METADATA_SIZE],
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = 0,
                },
                .{
                    .pubkey = spill_account_key,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = spill_balance + buffer_balance + program_data_balance - rent.minimumBalance(program_data_buffer.len),
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
            .accounts_resize_delta = -buffer_size,
        },
    );
}

test "executeV3ExtendProgram" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const payer_account_key = Pubkey.initRandom(prng.random());
    const upgrade_authority_key = Pubkey.initRandom(prng.random());

    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key = try pubkey_utils.createProgramAddress(
        &.{&program_account_key.data},
        &.{255},
        bpf_loader_program.v3.ID,
    );

    var clock = sysvar.Clock.DEFAULT;
    clock.slot += 1337;

    const program_data_account_buffer = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(program_data_account_buffer);
    const program_data = try bincode.writeToSlice(
        program_data_account_buffer,
        bpf_loader_program.v3.State{
            .program_data = .{
                .slot = clock.slot - 1, // must be before the current clock's slot.
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        .{},
    );

    const additional_bytes = 512;
    const help_pay = 100; // TODO
    const payer_balance = prng.random().uintAtMost(u32, 1024) + help_pay;
    const program_data_lamports =
        sysvar.Rent.DEFAULT.minimumBalance(program_data.len + additional_bytes) -
        help_pay;

    const extended_program_data_buffer = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State) + additional_bytes);
    defer allocator.free(extended_program_data_buffer);
    @memset(extended_program_data_buffer, 0); // important
    const extended_program_data = try bincode.writeToSlice(
        extended_program_data_buffer,
        bpf_loader_program.v3.State{ .program_data = .{
            .slot = clock.slot,
            .upgrade_authority_address = upgrade_authority_key,
        } },
        .{},
    );

    const program_account_buffer = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(program_account_buffer);
    const program_account = try bincode.writeToSlice(
        program_account_buffer,
        bpf_loader_program.v3.State{ .program = .{ .programdata_address = program_data_account_key } },
        .{},
    );

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3,
        bpf_loader_program.v3.Instruction{
            .extend_program = .{ .additional_bytes = additional_bytes },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 }, // programdata
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 }, // program
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 }, // loader
            .{ .is_signer = true, .is_writable = true, .index_in_transaction = 3 }, // payer
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 }, // system program
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_data_account_key,
                    .data = program_data,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = program_data_lamports,
                },
                .{
                    .pubkey = program_account_key,
                    .data = program_account,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
                .{
                    .pubkey = payer_account_key,
                    .lamports = payer_balance,
                },
                .{
                    .pubkey = system_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                    .executable = true,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS + system_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = sysvar.Rent.DEFAULT,
                .clock = clock,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_data_account_key,
                    .data = extended_program_data_buffer[0 .. extended_program_data.len + additional_bytes],
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = program_data_lamports + help_pay,
                },
                .{
                    .pubkey = program_account_key,
                    .data = program_account,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
                .{
                    .pubkey = payer_account_key,
                    .lamports = payer_balance - help_pay,
                },
            },
            .accounts_resize_delta = additional_bytes,
        },
    );
}
