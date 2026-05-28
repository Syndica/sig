const std14 = @import("../std14.zig");
const sig = @import("../lib.zig");

const vm = sig.vm;

const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

/// [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/transaction-context/src/lib.rs#L17
pub const MAX_ACCOUNTS_PER_INSTRUCTION = 255;

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/transaction-context/src/lib.rs#L41
pub const MAX_INSTRUCTION_TRACE_LENGTH = 64;

// https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/execution_budget.rs#L8
pub const MAX_INSTRUCTION_STACK_DEPTH = 5;

/// SIMD-0460: information captured by the SBPF memory map's access-violation
/// handler so the bpf_loader post-execution path can remap a generic
/// `AccessViolation` into a specific account-related `InstructionError`.
///
/// Sig differs from Agave here: Agave resolves handled account-growth accesses
/// inside the memory-mapping layer without persisting equivalent remap
/// metadata, while Sig keeps the last attempted access for post-execution
/// classification. `handled=true` means the handler successfully repaired the
/// access by growing the region far enough for the retry to succeed, so this
/// record must be ignored by `remapAccessViolation`.
pub const AccessViolationInfo = struct {
    access_type: vm.memory.MemoryState,
    vm_addr: u64,
    len: u64,
    handled: bool = false,
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L493
pub const TransactionReturnData = struct {
    program_id: Pubkey = Pubkey.ZEROES,
    data: std14.BoundedArray(u8, MAX_RETURN_DATA) = .{},

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/95764e268fe33a19819e6f9f411ff9e732cbdf0d/cpi/src/lib.rs#L329
    pub const MAX_RETURN_DATA: usize = 1024;
};

/// Represents an account within a transaction and provides single threaded
/// read/write access to the account data to prevent invalid access during cpi.
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L137-L139
pub const TransactionContextAccount = struct {
    pubkey: Pubkey,
    account: *AccountSharedData,
    read_refs: usize = 0,
    write_ref: bool = false,

    pub const RLockGuard = struct {
        read_refs: *usize,

        pub fn release(self: RLockGuard) void {
            self.read_refs.* -= 1;
        }
    };

    pub const WLockGuard = struct {
        write_ref: *bool,

        pub fn release(self: WLockGuard) void {
            self.write_ref.* = false;
        }
    };

    pub fn init(pubkey: Pubkey, account: *AccountSharedData) TransactionContextAccount {
        return .{
            .pubkey = pubkey,
            .account = account,
            .read_refs = 0,
            .write_ref = false,
        };
    }

    pub fn writeWithLock(
        self: *TransactionContextAccount,
    ) ?struct { *AccountSharedData, WLockGuard } {
        if (self.write_ref or self.read_refs > 0) return null;
        self.write_ref = true;
        return .{ self.account, .{ .write_ref = &self.write_ref } };
    }

    pub fn readWithLock(
        self: *TransactionContextAccount,
    ) ?struct { *AccountSharedData, RLockGuard } {
        if (self.write_ref) return null;
        self.read_refs += 1;
        return .{ self.account, .{ .read_refs = &self.read_refs } };
    }
};
