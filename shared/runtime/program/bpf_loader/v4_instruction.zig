pub const Write = struct {
    /// Offset at which to write the given bytes.
    offset: u32,
    /// Serialized program data
    bytes: []const u8,

    pub const AccountIndex = enum(u1) {
        /// `[WRITE]` The program account to write to.
        account = 0,
        /// `[SIGNER]` The authority of the program.
        authority = 1,
    };
};

pub const Copy = struct {
    /// Offset at which to write.
    destination_offset: u32,
    /// Offset at which to read.
    source_offset: u32,
    /// Amount of bytes to copy.
    length: u32,

    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The program account to write to.
        dst_account = 0,
        /// `[SIGNER]` The authority of the program.
        authority = 1,
        // `[]` The program account to copy from.
        src_account = 2,
    };
};

pub const SetProgramLength = struct {
    /// The new size after the operation.
    new_size: u32,

    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The program account to change the size of.
        account = 0,
        /// `[SIGNER]` The authority of the program.
        authority = 1,
        // `[WRITE]` Optional, the recipient account.
        recipient = 2,
    };
};

pub const Deploy = struct {
    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The program account to deploy.
        account = 0,
        /// `[SIGNER]` The authority of the program.
        authority = 1,
        /// `[WRITE]` Optional, an undeployed source program account to take data and lamports from.
        provider = 2,
    };
};

pub const Retract = struct {
    pub const AccountIndex = enum(u1) {
        /// `[WRITE]` The program account to retract.
        account = 0,
        /// `[SIGNER]` The authority of the program.
        authority = 1,
    };
};

pub const TransferAuthority = struct {
    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The program account to change the authority of.
        account = 0,
        /// `[SIGNER]` The current authority of the program.
        authority = 1,
        /// `[SIGNER]` The new authority of the program.
        new_authority = 2,
    };
};

pub const Finalize = struct {
    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The program account to change the authority of.
        account = 0,
        /// `[SIGNER]` The current authority of the program.
        authority = 1,
        /// `[]` The next version of the program (can be itself).
        new_authority = 2,
    };
};

/// [agave] https://docs.rs/solana-loader-v4-interface/latest/src/solana_loader_v4_interface/instruction.rs.html#15
pub const Instruction = union(enum) {
    /// Write ELF data into an undeployed program account.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to write to.
    ///   1. `[signer]` The authority of the program.
    write: Write,

    /// Copy ELF data into an undeployed program account.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to write to.
    ///   1. `[signer]` The authority of the program.
    ///   2. `[]` The program account to copy from.
    copy: Copy,

    /// Changes the size of an undeployed program account.
    ///
    /// A program account is automatically initialized when its size is first increased.
    /// In this initial truncate, this sets the authority needed for subsequent operations.
    /// Decreasing to size zero closes the program account and resets it into an uninitialized state.
    /// Closing the program requires a recipient account.
    /// Providing additional lamports upfront might be necessary to reach rent exemption.
    /// Superflous funds are transferred to the recipient account if provided.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to change the size of.
    ///   1. `[signer]` The authority of the program.
    ///   2. `[writable]` Optional, the recipient account.
    set_program_length: SetProgramLength,

    /// Verify the data of a program account to be a valid ELF.
    ///
    /// If this succeeds the program becomes executable, and is ready to use.
    /// A source program account can be provided to overwrite the data before deployment
    /// in one step, instead retracting the program and writing to it and redeploying it.
    /// The source program is truncated to zero (thus closed) and lamports necessary for
    /// rent exemption are transferred, in case that the source was bigger than the program.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to deploy.
    ///   1. `[signer]` The authority of the program.
    ///   2. `[writable]` Optional, an undeployed source program account to take data and lamports from.
    deploy: Deploy,

    /// Undo the deployment of a program account.
    ///
    /// The program is no longer executable and goes into maintenance.
    /// Necessary for writing data and truncating.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to retract.
    ///   1. `[signer]` The authority of the program.
    retract: Retract,

    /// Transfers the authority over a program account.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to change the authority of.
    ///   1. `[signer]` The current authority of the program.
    ///   2. `[signer]` The new authority of the program.
    transfer_authority: TransferAuthority,

    /// Finalizes the program account, rendering it immutable.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to change the authority of.
    ///   1. `[signer]` The current authority of the program.
    ///   2. `[]` The next version of the program (can be itself).
    finalize: Finalize,
};
