pub const InitializeBuffer = struct {
    pub const AccountIndex = enum(u1) {
        /// `[WRITE]` source account to initialize.
        account = 0,
        /// `[]` Buffer authority, optional, if omitted then the buffer will be immutable.
        authority = 1,
    };
};

pub const Write = struct {
    /// Offset at which to write the given bytes.
    offset: u32,
    /// Serialized program data
    bytes: []const u8,

    pub const AccountIndex = enum(u1) {
        /// `[WRITE]` Buffer account to write program data to.
        account = 0,
        /// `[SIGNER]` Buffer authority.
        authority = 1,
    };
};

pub const DeployWithMaxDataLen = struct {
    /// Maximum length that the program can be upgraded to.
    max_data_len: usize,

    pub const AccountIndex = enum(u3) {
        /// `[WRITE, SIGNER]` The payer account that will pay to create the ProgramData account.
        payer = 0,
        /// `[WRITE]` The uninitialized ProgramData account.
        program_data = 1,
        /// `[WRITE]` The uninitialized Program account.
        program = 2,
        /// `[WRITE]` The Buffer account where the program data has been written.
        /// The buffer account's authority must match the program's authority.
        buffer = 3,
        /// `[]` Rent sysvar.
        rent = 4,
        /// `[]` Clock sysvar.
        clock = 5,
        /// `[]` System program (`solana_sdk::system_program::id()`).
        system_program = 6,
        /// `[SIGNER]` The program's authority.
        authority = 7,
    };
};

pub const Upgrade = struct {
    pub const AccountIndex = enum(u7) {
        /// `[WRITE]` The ProgramData account.
        program_data = 0,
        /// `[WRITE]` The Program account.
        program = 1,
        /// `[WRITE]` The Buffer account where the program data has been written.
        /// The buffer account's authority must match the program's authority.
        buffer = 2,
        /// `[WRITE]` The spill account.
        spill = 3,
        /// `[]` Rent sysvar.
        rent = 4,
        /// `[]` Clock sysvar.
        clock = 5,
        /// `[SIGNER]` The program's authority.
        authority = 6,
    };
};

pub const SetAuthority = struct {
    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The Buffer or ProgramData account to change the authority of.
        account = 0,
        /// `[SIGNER]` The current authority.
        present_authority = 1,
        /// `[]` The new authority, optional, if omitted then the program will not be upgradeable.
        new_authority = 2,
    };
};

pub const SetAuthorityChecked = struct {
    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The Buffer or ProgramData account to change the authority of.
        account = 0,
        /// `[SIGNER]` The current authority.
        present_authority = 1,
        /// `[SIGNER]` The new authority.
        new_authority = 2,
    };
};

pub const Close = struct {
    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The account to close, if closing a program must be the ProgramData account.
        account = 0,
        /// `[WRITE]` The account to deposit the closed account's lamports.
        recipient = 1,
        /// `[SIGNER]` The account's authority, Optional, required for initialized accounts.
        authority = 2,
        /// `[WRITE]` The associated Program account if the account to close is a ProgramData account.
        program = 3,
    };
};

pub const ExtendProgram = struct {
    /// Number of bytes to extend the program data.
    additional_bytes: u32,

    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The ProgramData account.
        program_data = 0,
        /// `[WRITE]` The ProgramData account's associated Program account.
        program = 1,
        /// `[]` System program (`solana_sdk::system_program::id()`),
        /// optional used to transfer lamports from the payer to the ProgramData account.
        system_program = 2,
        /// `[WRITE, SIGNER]` The payer account, optional, that will pay necessary rent exemption
        /// costs for the increased storage size.
        payer = 3,
    };
};

pub const Migrate = struct {
    pub const AccountIndex = enum(u2) {
        /// `[WRITE]` The ProgramData account.
        program_data = 0,
        /// `[WRITE]` The Program account.
        program = 1,
        /// `[SIGNER]` The current authority.
        authority = 2,
    };
};

/// [agave] https://github.com/anza-xyz/agave/blob/master/sdk/program/src/loader_upgradeable_instruction.rs#L7
pub const Instruction = union(enum) {
    /// Initialize a Buffer account.
    ///
    /// A Buffer account is an intermediary that once fully populated is used
    /// with the `DeployWithMaxDataLen` instruction to populate the program's
    /// ProgramData account.
    ///
    /// The `InitializeBuffer` instruction requires no signers and MUST be
    /// included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party may initialize the account.
    ///
    /// # Account references
    ///   0. `[writable]` source account to initialize.
    ///   1. `[]` Buffer authority, optional, if omitted then the buffer will be
    ///      immutable.
    initialize_buffer: InitializeBuffer,

    /// Write program data into a Buffer account.
    ///
    /// # Account references
    ///   0. `[writable]` Buffer account to write program data to.
    ///   1. `[signer]` Buffer authority
    write: Write,

    /// Deploy an executable program.
    ///
    /// A program consists of a Program and ProgramData account pair.
    ///   - The Program account's address will serve as the program id for any
    ///     instructions that execute this program.
    ///   - The ProgramData account will remain mutable by the loader only and
    ///     holds the program data and authority information.  The ProgramData
    ///     account's address is derived from the Program account's address and
    ///     created by the DeployWithMaxDataLen instruction.
    ///
    /// The ProgramData address is derived from the Program account's address as
    /// follows:
    ///
    /// ```
    /// # use solana_program::pubkey::Pubkey;
    /// # use solana_program::bpf_loader_upgradeable;
    /// # let program_address = &[];
    /// let (program_data_address, _) = Pubkey::find_program_address(
    ///      &[program_address],
    ///      &bpf_loader_upgradeable::id()
    ///  );
    /// ```
    ///
    /// The `DeployWithMaxDataLen` instruction does not require the ProgramData
    /// account be a signer and therefore MUST be included within the same
    /// Transaction as the system program's `CreateAccount` instruction that
    /// creates the Program account. Otherwise another party may initialize the
    /// account.
    ///
    /// # Account references
    ///   0. `[writable, signer]` The payer account that will pay to create the
    ///      ProgramData account.
    ///   1. `[writable]` The uninitialized ProgramData account.
    ///   2. `[writable]` The uninitialized Program account.
    ///   3. `[writable]` The Buffer account where the program data has been
    ///      written.  The buffer account's authority must match the program's
    ///      authority
    ///   4. `[]` Rent sysvar.
    ///   5. `[]` Clock sysvar.
    ///   6. `[]` System program (`solana_sdk::system_program::id()`).
    ///   7. `[signer]` The program's authority
    deploy_with_max_data_len: DeployWithMaxDataLen,

    /// Upgrade a program.
    ///
    /// A program can be updated as long as the program's authority has not been
    /// set to `None`.
    ///
    /// The Buffer account must contain sufficient lamports to fund the
    /// ProgramData account to be rent-exempt, any additional lamports left over
    /// will be transferred to the spill account, leaving the Buffer account
    /// balance at zero.
    ///
    /// # Account references
    ///   0. `[writable]` The ProgramData account.
    ///   1. `[writable]` The Program account.
    ///   2. `[writable]` The Buffer account where the program data has been
    ///      written.  The buffer account's authority must match the program's
    ///      authority
    ///   3. `[writable]` The spill account.
    ///   4. `[]` Rent sysvar.
    ///   5. `[]` Clock sysvar.
    ///   6. `[signer]` The program's authority.
    upgrade: Upgrade,

    /// Set a new authority that is allowed to write the buffer or upgrade the
    /// program.  To permanently make the buffer immutable or disable program
    /// updates omit the new authority.
    ///
    /// # Account references
    ///   0. `[writable]` The Buffer or ProgramData account to change the
    ///      authority of.
    ///   1. `[signer]` The current authority.
    ///   2. `[]` The new authority, optional, if omitted then the program will
    ///      not be upgradeable.
    set_authority: SetAuthority,

    /// Closes an account owned by the upgradeable loader of all lamports and
    /// withdraws all the lamports
    ///
    /// # Account references
    ///   0. `[writable]` The account to close, if closing a program must be the
    ///      ProgramData account.
    ///   1. `[writable]` The account to deposit the closed account's lamports.
    ///   2. `[signer]` The account's authority, Optional, required for
    ///      initialized accounts.
    ///   3. `[writable]` The associated Program account if the account to close
    ///      is a ProgramData account.
    close: Close,

    /// Extend a program's ProgramData account by the specified number of bytes.
    /// Only upgradeable program's can be extended.
    ///
    /// The payer account must contain sufficient lamports to fund the
    /// ProgramData account to be rent-exempt. If the ProgramData account
    /// balance is already sufficient to cover the rent exemption cost
    /// for the extended bytes, the payer account is not required.
    ///
    /// # Account references
    ///   0. `[writable]` The ProgramData account.
    ///   1. `[writable]` The ProgramData account's associated Program account.
    ///   2. `[]` System program (`solana_sdk::system_program::id()`), optional, used to transfer
    ///      lamports from the payer to the ProgramData account.
    ///   3. `[writable, signer]` The payer account, optional, that will pay
    ///       necessary rent exemption costs for the increased storage size.
    extend_program: ExtendProgram,

    /// Set a new authority that is allowed to write the buffer or upgrade the
    /// program.
    ///
    /// This instruction differs from SetAuthority in that the new authority is a
    /// required signer.
    ///
    /// # Account references
    ///   0. `[writable]` The Buffer or ProgramData account to change the
    ///      authority of.
    ///   1. `[signer]` The current authority.
    ///   2. `[signer]` The new authority.
    set_authority_checked: SetAuthorityChecked,

    /// Migrate the program to loader-v4.
    ///
    /// # Account references
    ///   0. `[writable]` The ProgramData account.
    ///   1. `[writable]` The Program account.
    ///   2. `[signer]` The current authority.
    migrate: Migrate,
};
