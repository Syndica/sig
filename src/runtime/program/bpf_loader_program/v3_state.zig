const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/5fb000f27e476add032e08a1de9e89310b0eab4b/sdk/program/src/bpf_loader_upgradeable.rs#L29
pub const State = union(enum) {
    /// Account is not initialized.
    uninitialized,
    /// A Buffer account.
    buffer: struct {
        /// Authority address
        authority_address: ?Pubkey,
        // The raw program data follows this serialized structure in the
        // account's data.
    },
    /// An Program account.
    program: struct {
        /// Address of the ProgramData account.
        programdata_address: Pubkey,
    },
    // A ProgramData account.
    program_data: struct {
        /// Slot that the program was last modified.
        slot: u64,
        /// Address of the Program's upgrade authority.
        upgrade_authority_address: ?Pubkey,
        // The raw program data follows this serialized structure in the
        // account's data.
    },

    pub const UNINITIALIZED_SIZE: usize = 4;
    pub const BUFFER_METADATA_SIZE: usize = 37;
    pub const PROGRAM_SIZE: usize = 36;
    pub const PROGRAM_DATA_METADATA_SIZE: usize = 45;

    pub fn serializedSize(self: State) !usize {
        return switch (self) {
            .uninitialized => UNINITIALIZED_SIZE,
            .buffer => BUFFER_METADATA_SIZE,
            .program => PROGRAM_SIZE,
            .program_data => PROGRAM_DATA_METADATA_SIZE,
        };
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/c07f692e41d757057c8700211a9300cdcd6d33b1/loader-v3-interface/src/state.rs#L57
    pub fn sizeOfBuffer(program_len: usize) usize {
        return BUFFER_METADATA_SIZE +| program_len;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/c07f692e41d757057c8700211a9300cdcd6d33b1/loader-v3-interface/src/state.rs#L62
    pub fn sizeOfProgramData(program_len: usize) usize {
        return PROGRAM_DATA_METADATA_SIZE +| program_len;
    }
};
