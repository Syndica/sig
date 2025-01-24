const std = @import("std");
const sig = @import("../sig.zig");

const AccountSharedData = sig.runtime.AccountSharedData;
const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/transaction-context/src/lib.rs#L754
pub const BorrowedAccount = struct {
    pubkey: Pubkey,
    account: sig.sync.mux.Mutable(AccountSharedData),
    account_write_guard: sig.sync.RwMux(AccountSharedData).WLockGuard,

    /// Releases the write guard on the account.
    pub fn deinit(self: BorrowedAccount) void {
        self.account_write_guard.unlock();
    }

    pub fn getPubkey(self: BorrowedAccount) Pubkey {
        return self.pubkey;
    }

    pub fn getLamports(self: BorrowedAccount) u64 {
        return self.account.lamports;
    }

    pub fn getData(self: BorrowedAccount) []u8 {
        return self.account.data;
    }

    pub fn getOwner(self: BorrowedAccount) Pubkey {
        return self.account.owner;
    }

    /// Calls `T.deserialize` on the account data and returns the result.
    /// If deserialization fails, returns an `InstructionError.InvalidAccountData`.
    pub fn getState(self: BorrowedAccount, comptime T: type) InstructionError.InvalidAccountData!T {
        return T.deserialize(self.account.data) catch .InvalidAccountData;
    }

    /// Returns `true` if the account data is non-empty.
    pub fn hasData(self: BorrowedAccount) bool {
        return self.account.data.len > 0;
    }

    /// Returns `true` if the account is writable.
    pub fn isWritable(self: BorrowedAccount) bool {
        return self.account.is_writable;
    }

    /// Performs checked addition of `lamports` to the account balance.
    /// Returns an `InstructionError.ArithmeticOverflow` if the addition overflows.
    pub fn addLamports(self: *BorrowedAccount, lamports: u64) InstructionError.ArithmeticOverflow!void {
        self.account.lamports = std.math.add(u64, self.account.lamports, lamports) catch {
            return .ArithmeticOverflow;
        };
    }

    /// Performs checked subtraction of `lamports` from the account balance.
    /// Returns an `InstructionError.ArithmeticOverflow` if the subtraction underflows.
    pub fn subtractLamports(self: *BorrowedAccount, lamports: u64) InstructionError.ArithmeticOverflow!void {
        self.account.lamports = std.math.sub(u64, self.account.lamports, lamports) catch {
            return .ArithmeticOverflow;
        };
    }

    pub fn setDataLength(account: BorrowedAccount, length: usize) InstructionError!void {
        // TODO: implement
        _ = account;
        _ = length;
    }

    pub fn setOwner(account: BorrowedAccount, owner: Pubkey) InstructionError!void {
        // TODO: implement
        _ = account;
        _ = owner;
    }

    pub fn setState(account: BorrowedAccount, comptime T: type, state: T) InstructionError!void {
        // TODO: implement
        _ = account;
        _ = state;
    }
};
