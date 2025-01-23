// https://github.com/anza-xyz/agave/blob/df5c9ad28e76fb487514ab7719358df3c42cb1d5/sdk/program/src/loader_instruction.rs#L12

pub const BpfLoaderInstruction = union(enum) {
    /// Write program data into an account
    ///
    /// # Account references
    ///   0. [WRITE, SIGNER] Account to write to
    Write: struct {
        /// Offset at which to write the given bytes
        offset: u32,

        /// Serialized program data
        bytes: []const u8,
    },

    /// Finalize an account loaded with program data for execution
    ///
    /// The exact preparation steps is loader specific but on success the loader must set the executable
    /// bit of the account.
    ///
    /// # Account references
    ///   0. [WRITE, SIGNER] The account to prepare for execution
    ///   1. [] Rent sysvar
    Finalize,
};
