const std = @import("std");
const sig = @import("../sig.zig");

const RwMux = sig.sync.RwMux;
const Mutable = sig.sync.mux.Mutable;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const ExecuteTransactionContext = sig.runtime.ExecuteTransactionContext;
const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

const MAX_PERMITTED_DATA_LENGTH = sig.runtime.program.system_program.MAX_PERMITTED_DATA_LENGTH;

// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/transaction-context/src/lib.rs#L754
pub const BorrowedAccount = struct {
    eic: *const ExecuteInstructionContext,
    /// Instruction level account information
    eic_info: *const ExecuteInstructionContext.AccountInfo,
    /// Transaction level account information
    etc_info: Mutable(ExecuteTransactionContext.AccountInfo),
    /// Write guard over the transaction level account information
    etc_info_write_guard: RwMux(ExecuteTransactionContext.AccountInfo).WLockGuard,

    /// Releases the write guard on the account.
    pub fn release(self: *BorrowedAccount) void {
        self.etc_info_write_guard.unlock();
    }

    /// Returns an error if the account data can not be mutated by the current program
    /// https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L1077-L1078
    pub fn checkDataCanBeChanged(self: BorrowedAccount) InstructionError!void {
        if (self.isExecutable()) return InstructionError.ExecutableDataModified;
        if (!self.isWritable()) return InstructionError.ReadonlyDataModified;
        if (!self.isOwnedByCurrentProgram()) return InstructionError.ExternalAccountDataModified;
    }

    /// Returns an error if the account data can not be resized by the current program
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L1095
    pub fn checkDataCanBeResized(self: BorrowedAccount, length: usize) InstructionError!void {
        const old_length = self.getData().len;
        if (length != old_length and !self.isOwnedByCurrentProgram())
            return InstructionError.AccountDataSizeChanged;
        if (length > MAX_PERMITTED_DATA_LENGTH) return InstructionError.InvalidRealloc;
        try self.eic.etc.checkAccountsResizeDelta(@intCast(length -| old_length));
    }

    /// Returns the public key of this account (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L728
    pub fn getPubkey(self: BorrowedAccount) Pubkey {
        return self.eic_info.pubkey;
    }

    /// Returns the number of lamports of this account (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L770
    pub fn getLamports(self: BorrowedAccount) u64 {
        return self.etc_info.account.lamports;
    }

    /// Returns a read-only slice of the account data (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L820
    pub fn getData(self: BorrowedAccount) []const u8 {
        return self.etc_info.account.data.items;
    }

    /// Returns a writable slice of the account data (transaction wide)
    /// https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L826
    pub fn getDataMutable(self: BorrowedAccount) ![]u8 {
        try self.checkDataCanBeChanged();
        try self.touch();
        return self.etc_info.account.data.items;
    }

    /// Returns the owner of this account (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L736
    pub fn getOwner(self: BorrowedAccount) Pubkey {
        return self.etc_info.account.owner;
    }

    /// Deserializes the account data into a `T` via `T.deserialize(allocator, data)`.
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L968-L969
    pub fn getState(
        self: BorrowedAccount,
        allocator: std.mem.Allocator,
        comptime T: type,
    ) error{InvalidAccountData}!T {
        return sig.bincode.readFromSlice(
            allocator,
            T,
            self.getData(),
            .{},
        ) catch error.InvalidAccountData;
    }

    /// Returns `true` if the account data is non-empty.
    pub fn hasData(self: BorrowedAccount) bool {
        return self.getData().len > 0;
    }

    /// Returns whether this account is writable (instruction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L1055
    pub fn isWritable(self: BorrowedAccount) bool {
        return self.eic_info.is_writable;
    }

    /// Returns whether this account is executable (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L998-L999
    pub fn isExecutable(self: BorrowedAccount) bool {
        return self.etc_info.account.executable;
    }

    /// Returns `true` if the account data is zeroed or empty.
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L756
    pub fn isDataZeroedOrEmpty(self: BorrowedAccount) bool {
        for (self.getData()) |byte| if (byte != 0) return false;
        return true;
    }

    /// Returns true if the owner of this account is the current `InstructionContext`s last program (instruction wide)
    /// https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L1068-L1069
    pub fn isOwnedByCurrentProgram(self: BorrowedAccount) bool {
        return self.eic.program_id.equals(&self.getOwner());
    }

    /// Adds `lamports` to this account (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L800
    pub fn addLamports(
        self: *BorrowedAccount,
        lamports: u64,
    ) error{ArithmeticOverflow}!void {
        self.etc_info.account.lamports = std.math.add(
            u64,
            self.etc_info.account.lamports,
            lamports,
        ) catch {
            return InstructionError.ArithmeticOverflow;
        };
    }

    /// Subtracts `lamports` from this account (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L808
    pub fn subtractLamports(
        self: *BorrowedAccount,
        lamports: u64,
    ) error{ArithmeticOverflow}!void {
        self.etc_info.account.lamports = std.math.sub(
            u64,
            self.etc_info.account.lamports,
            lamports,
        ) catch {
            return InstructionError.ArithmeticOverflow;
        };
    }

    /// Resizes the account data (transaction wide)
    /// Fills it with zeros at the end if is extended or truncates at the end otherwise.
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L885
    pub fn setDataLength(
        self: BorrowedAccount,
        allocator: std.mem.Allocator,
        length: usize,
    ) !void {
        try self.checkDataCanBeResized(length);
        try self.checkDataCanBeChanged();
        if (self.getData().len == length) return;
        try self.touch();
        try self.updateAccountsResizeDelta(length);
        try self.etc_info.account.resize(allocator, length);
    }

    /// Assignes the owner of this account (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L742
    pub fn setOwner(self: BorrowedAccount, owner: Pubkey) InstructionError!void {
        if (!self.isOwnedByCurrentProgram() or
            !self.isWritable() or
            self.isExecutable() or
            !self.isDataZeroedOrEmpty()) return InstructionError.ModifiedProgramId;

        if (!self.getOwner().equals(&owner)) {
            try self.touch();
            self.etc_info.account.owner = owner;
        }
    }

    /// Serializes a state into the account data
    /// T must implement `T.serializedSize()` and `T.writeToSlice(slice: []u8)`.
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L976
    pub fn setState(self: BorrowedAccount, comptime T: type, state: T) InstructionError!void {
        const data = try self.getDataMutable();
        const serialized_size = state.serializedSize() catch error.GenericError;
        if (serialized_size > data.len) return InstructionError.AccountDataTooSmall;
        const written = sig.bincode.writeToSlice(
            data,
            state,
            .{},
        ) catch return InstructionError.GenericError;
        if (written.len != serialized_size) return InstructionError.GenericError;
    }

    /// Touches the account (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L1119
    pub fn touch(self: BorrowedAccount) !void {
        self.etc_info.touched = true;
    }

    /// Updates the accounts resize delta (transaction wide)
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L1126-L1127
    pub fn updateAccountsResizeDelta(self: BorrowedAccount, length: usize) !void {
        self.eic.etc.addAccountsResizeDelta(@intCast(length -| self.getData().len));
    }
};
