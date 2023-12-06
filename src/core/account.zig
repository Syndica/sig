const Pubkey = @import("pubkey.zig").Pubkey;
const Epoch = @import("./clock.zig").Epoch;

pub const Account = struct {
    lamports: u64,
    data: []u8,
    owner: Pubkey,
    executable: bool,
    rent_epoch: Epoch,
};
