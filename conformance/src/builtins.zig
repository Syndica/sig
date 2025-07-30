const sig = @import("sig");

const program = sig.runtime.program;
const features = sig.core.features;

const Pubkey = sig.core.Pubkey;

// Live source buffer accounts for builtin migrations
const STAKE_PROGRAM_SOURCE_BUFFER_ADDRESS =
    Pubkey.parseBase58String("8t3vv6v99tQA6Gp7fVdsBH66hQMaswH5qsJVqJqo8xvG") catch unreachable;
const CONFIG_PROGRAM_SOURCE_BUFFER_ADDRESS =
    Pubkey.parseBase58String("BuafH9fBv62u6XjzrzS4ZjAE8963ejqF5rt1f8Uga4Q3") catch unreachable;
const ADDRESS_LOOKUP_TABLE_SOURCE_BUFFER_ADDRESS =
    Pubkey.parseBase58String("AhXWrD9BBUYcKjtpA3zuiiZG4ysbo6C6wjHo1QhERk6A") catch unreachable;
const FEATURE_PROGRAM_SOURCE_BUFFER_ADDRESSS =
    Pubkey.parseBase58String("3D3ydPWvmEszrSjrickCtnyRSJm1rzbbSsZog8Ub6vLh") catch unreachable;

/// Configuration for migrating a built-in program to Core BPF.
pub const CoreBpfMigrationConfig = struct {
    /// The program's ID.
    program_id: Pubkey,

    /// The address of the source buffer account to be used to replace the
    /// builtin.
    source_buffer_address: Pubkey,

    /// The authority to be used as the BPF program's upgrade authority.
    ///
    /// Note: If this value is set to `None`, then the migration will ignore
    /// the source buffer account's authority. If it's set to any `Some(..)`
    /// value, then the migration will perform a sanity check to ensure the
    /// source buffer account's authority matches the provided value.
    upgrade_authority_address: ?Pubkey,

    /// The feature gate to trigger the migration to Core BPF.
    /// Note: This feature gate should never be the same as any builtin's
    /// `enable_feature_id`. It should always be a feature gate that will be
    /// activated after the builtin is already enabled.
    enable_feature_id: Pubkey,
};

/// Transitions of built-in programs at epoch boundaries when features are activated.
pub const BuiltinProgram = struct {
    /// The program's ID.
    program_id: Pubkey,

    /// The data to store in the on-chain program account
    /// Typically the program's name, ie "system_program".
    data: []const u8,

    /// Feature ID that enables the builtin program.
    /// If None, the built-in program is always enabled.
    enable_feature_id: ?Pubkey,

    /// Configurations for migrating the builtin to Core BPF.
    core_bpf_migration_config: ?CoreBpfMigrationConfig,
};

/// Transitions of stateless built-in programs at epoch boundaries when
/// features are activated.
/// These are built-in programs that don't actually exist, but their address
/// is reserved.
pub const StatelessBuiltinPrototype = struct {
    /// The program's ID.
    program_id: Pubkey,
    /// Configurations for migrating the stateless builtin to Core BPF.
    core_bpf_migration_config: ?CoreBpfMigrationConfig,
};

pub const BUILTINS = [_]BuiltinProgram{
    .{
        .program_id = program.system.ID,
        .data = "system_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = null,
    },
    .{
        .program_id = program.vote.ID,
        .data = "vote_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = null,
    },
    .{
        .program_id = program.stake.ID,
        .data = "stake_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = .{
            .program_id = program.stake.ID,
            .source_buffer_address = STAKE_PROGRAM_SOURCE_BUFFER_ADDRESS,
            .upgrade_authority_address = null,
            .enable_feature_id = features.MIGRATE_STAKE_PROGRAM_TO_CORE_BPF,
        },
    },
    .{
        .program_id = program.config.ID,
        .data = "config_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = .{
            .program_id = program.config.ID,
            .source_buffer_address = CONFIG_PROGRAM_SOURCE_BUFFER_ADDRESS,
            .upgrade_authority_address = null,
            .enable_feature_id = features.MIGRATE_CONFIG_PROGRAM_TO_CORE_BPF,
        },
    },
    .{
        .program_id = program.address_lookup_table.ID,
        .data = "address_lookup_table_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = .{
            .program_id = program.address_lookup_table.ID,
            .source_buffer_address = ADDRESS_LOOKUP_TABLE_SOURCE_BUFFER_ADDRESS,
            .upgrade_authority_address = null,
            .enable_feature_id = features.MIGRATE_ADDRESS_LOOKUP_TABLE_PROGRAM_TO_CORE_BPF,
        },
    },
    .{
        .program_id = program.bpf_loader.v1.ID,
        .data = "solana_bpf_loader_deprecated_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = null,
    },
    .{
        .program_id = program.bpf_loader.v2.ID,
        .data = "solana_bpf_loader_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = null,
    },
    .{
        .program_id = program.bpf_loader.v3.ID,
        .data = "solana_bpf_loader_upgradeable_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = null,
    },
    .{
        .program_id = program.bpf_loader.v4.ID,
        .data = "loader_v4",
        .enable_feature_id = features.ENABLE_LOADER_V4,
        .core_bpf_migration_config = null,
    },
    .{
        .program_id = program.compute_budget.ID,
        .data = "compute_budget_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = null,
    },
    .{
        .program_id = sig.runtime.ids.ZK_TOKEN_PROOF_PROGRAM_ID,
        .data = "zk_token_proof_program",
        .enable_feature_id = features.ZK_TOKEN_SDK_ENABLED,
        .core_bpf_migration_config = null,
    },
    .{
        .program_id = sig.runtime.ids.ZK_ELGAMAL_PROOF_PROGRAM_ID,
        .data = "zk_elgamal_proof_program",
        .enable_feature_id = features.ZK_ELGAMAL_PROOF_PROGRAM_ENABLED,
        .core_bpf_migration_config = null,
    },
};

pub const STATELESS_BUILTINS = [_]StatelessBuiltinPrototype{
    .{
        .program_id = sig.runtime.ids.FEATURE_PROGRAM_ID,
        .core_bpf_migration_config = .{
            .program_id = sig.runtime.ids.FEATURE_PROGRAM_ID,
            .source_buffer_address = FEATURE_PROGRAM_SOURCE_BUFFER_ADDRESSS,
            .upgrade_authority_address = null,
            .enable_feature_id = features.MIGRATE_FEATURE_GATE_PROGRAM_TO_CORE_BPF,
        },
    },
};
