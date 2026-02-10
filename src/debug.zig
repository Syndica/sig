const std = @import("std");
const sig = @import("sig.zig");

const Allocator = std.mem.Allocator;

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const LtHash = sig.core.LtHash;
const Ancestors = sig.core.Ancestors;
const AccountReader = sig.accounts_db.AccountReader;
const AccountSharedData = sig.runtime.AccountSharedData;
const InstructionErrorEnum = sig.core.instruction.InstructionErrorEnum;
const TransactionError = sig.ledger.transaction_status.TransactionError;

// Slots to print debug info for. Add slots of interest here.
const SLOTS = [_]Slot{
    386300416,
};

// Accounts to print in full (with data)
const FULL_ACCOUNTS = [_]Pubkey{};

pub fn is_debug_slot(slot: Slot) bool {
    return std.mem.indexOfScalar(Slot, &SLOTS, slot) != null;
}

pub fn fmtAccount(allocator: Allocator, address: *const Pubkey, account: *const AccountSharedData) ![]const u8 {
    const result = try std.fmt.allocPrint(
        allocator,
        "address={} lamports={} owner={} executable={} rent_epoch={} data_len={}",
        .{
            address,
            account.lamports,
            account.owner,
            account.executable,
            account.rent_epoch,
            account.data.len,
        },
    );
    defer allocator.free(result);

    if (for (FULL_ACCOUNTS) |addr| {
        if (addr.equals(address)) break true;
    } else false) {
        return std.fmt.allocPrint(allocator, "{s} data={x}", .{ result, account.data });
    } else {
        const hash = sig.core.Hash.init(account.data);
        return std.fmt.allocPrint(allocator, "{s} data_hash={}", .{ result, hash });
    }
}

fn fmtInstructionErrorRust(allocator: Allocator, err: InstructionErrorEnum) ![]const u8 {
    return switch (err) {
        .Custom => |code| try std.fmt.allocPrint(allocator, "Custom({d})", .{code}),
        .BorshIoError => |msg| try std.fmt.allocPrint(allocator, "BorshIoError(\"{s}\")", .{msg}),
        else => try allocator.dupe(u8, @tagName(err)),
    };
}

pub fn fmtTransactionErrorRust(allocator: Allocator, err: TransactionError) ![]const u8 {
    return switch (err) {
        .InstructionError => |ie| {
            const inner = try fmtInstructionErrorRust(allocator, ie[1]);
            defer allocator.free(inner);
            return std.fmt.allocPrint(allocator, "Err(InstructionError({d}, {s}))", .{ ie[0], inner });
        },
        .DuplicateInstruction => |idx| try std.fmt.allocPrint(allocator, "Err(DuplicateInstruction({d}))", .{idx}),
        .InsufficientFundsForRent => |s| try std.fmt.allocPrint(allocator, "Err(InsufficientFundsForRent {{ account_index: {d} }})", .{s.account_index}),
        .ProgramExecutionTemporarilyRestricted => |s| try std.fmt.allocPrint(allocator, "Err(ProgramExecutionTemporarilyRestricted {{ account_index: {d} }})", .{s.account_index}),
        else => try std.fmt.allocPrint(allocator, "Err({s})", .{@tagName(err)}),
    };
}
