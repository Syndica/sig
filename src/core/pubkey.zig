const shared_pubkey = @import("shared").core.pubkey;

pub const Pubkey = shared_pubkey.Pubkey;

const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
