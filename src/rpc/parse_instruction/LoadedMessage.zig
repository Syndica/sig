const std = @import("std");
const sig = @import("../../sig.zig");
const this_mod = @import("lib.zig");

const AccountKeys = this_mod.AccountKeys;
const Message = sig.core.transaction.Message;
const Pubkey = sig.core.Pubkey;

const LoadedMessage = @This();

message: Message,
loaded_addresses: sig.ledger.transaction_status.LoadedAddresses,
is_writable_account_cache: std.ArrayListUnmanaged(bool),

pub fn init(
    allocator: std.mem.Allocator,
    message: Message,
    loaded_addresses: sig.ledger.transaction_status.LoadedAddresses,
    reserved_account_keys: *const sig.utils.collections.PubkeyMap(void),
) !LoadedMessage {
    var loaded_message = LoadedMessage{
        .message = message,
        .loaded_addresses = loaded_addresses,
        .is_writable_account_cache = std.ArrayListUnmanaged(bool).empty,
    };
    try loaded_message.setIsWritableAccountCache(allocator, reserved_account_keys);
    return loaded_message;
}

pub fn deinit(
    self: *LoadedMessage,
    allocator: std.mem.Allocator,
) void {
    self.is_writable_account_cache.deinit(allocator);
}

fn setIsWritableAccountCache(
    self: *LoadedMessage,
    allocator: std.mem.Allocator,
    reserved_account_keys: *const sig.utils.collections.PubkeyMap(void),
) !void {
    const account_keys_len = self.accountKeys().len();
    for (0..account_keys_len) |i| {
        try self.is_writable_account_cache.append(allocator, self.isWritableInternal(
            i,
            reserved_account_keys,
        ));
    }
}

pub fn accountKeys(self: LoadedMessage) AccountKeys {
    return AccountKeys.init(
        self.message.account_keys,
        self.loaded_addresses,
    );
}

pub fn staticAccountKeys(self: LoadedMessage) []const Pubkey {
    return self.message.account_keys;
}

fn isWritableIndex(
    self: LoadedMessage,
    key_index: usize,
) bool {
    const header = struct {
        num_required_signatures: u8,
        num_readonly_signed_accounts: u8,
        num_readonly_unsigned_accounts: u8,
    }{
        .num_required_signatures = self.message.signature_count,
        .num_readonly_signed_accounts = self.message.readonly_signed_count,
        .num_readonly_unsigned_accounts = self.message.readonly_unsigned_count,
    };
    const num_account_keys = self.message.account_keys.len;
    const num_signed_accounts: usize = @intCast(header.num_required_signatures);
    if (key_index >= num_account_keys) {
        const loaded_addresses_index = key_index -| num_account_keys;
        return loaded_addresses_index < self.loaded_addresses.writable.len;
    } else if (key_index >= num_signed_accounts) {
        const num_unsigned_accounts = num_account_keys -| num_signed_accounts;
        const num_writable_unsigned_accounts = num_unsigned_accounts -| std.math.cast(
            usize,
            header.num_readonly_unsigned_accounts,
        ).?;
        const unsigned_account_index = key_index -| num_signed_accounts;
        return unsigned_account_index < num_writable_unsigned_accounts;
    } else {
        const num_writable_signed_accounts = num_signed_accounts -| std.math.cast(
            usize,
            header.num_readonly_signed_accounts,
        ).?;
        return key_index < num_writable_signed_accounts;
    }
}

fn isWritableInternal(
    self: LoadedMessage,
    key_index: usize,
    reserved_account_keys: *const sig.utils.collections.PubkeyMap(void),
) bool {
    if (!self.isWritableIndex(key_index)) return false;
    return if (self.accountKeys().get(key_index)) |key|
        !(reserved_account_keys.contains(key) or self.demoteProgramId(key_index))
    else
        false;
}

pub fn isWritable(self: LoadedMessage, key_index: usize) bool {
    if (key_index >= self.is_writable_account_cache.items.len) return false;
    return self.is_writable_account_cache.items[key_index];
}

pub fn isSigner(self: LoadedMessage, i: usize) bool {
    return i < std.math.cast(usize, self.message.signature_count).?;
}

pub fn demoteProgramId(self: LoadedMessage, i: usize) bool {
    return self.isKeyCalledAsProgram(i) and !self.isUpgradeableLoaderPresent();
}

/// Returns true if the account at the specified index is called as a program by an instruction
pub fn isKeyCalledAsProgram(self: LoadedMessage, key_index: usize) bool {
    const idx = std.math.cast(u8, key_index) orelse return false;
    for (self.message.instructions) |ixn| if (ixn.program_index == idx) return true;
    return false;
}

/// Returns true if any account is the bpf upgradeable loader
pub fn isUpgradeableLoaderPresent(self: LoadedMessage) bool {
    const keys = self.accountKeys();
    const total_len = keys.len();
    for (0..total_len) |i| {
        const account_key = keys.get(i).?;
        if (account_key.equals(&sig.runtime.program.bpf_loader.v3.ID)) return true;
    }
    return false;
}
