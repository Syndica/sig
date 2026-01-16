const sig = @import("../../sig.zig");

const program = sig.runtime.program;
const features = sig.core.features;

const Feature = features.Feature;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;

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
    enable_feature_id: Feature,

    /// If specified, the expected verifiable build hash of the bpf program.
    /// This will be checked against the buffer account before migration.
    verified_build_hash: ?Hash = null,
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
    enable_feature_id: ?Feature,

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
            .source_buffer_address = program.stake.SOURCE_ID,
            .upgrade_authority_address = null,
            .enable_feature_id = .migrate_stake_program_to_core_bpf,
            .verified_build_hash = null,
        },
    },
    .{
        .program_id = program.config.ID,
        .data = "config_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = .{
            .program_id = program.config.ID,
            .source_buffer_address = program.config.SOURCE_ID,
            .upgrade_authority_address = null,
            .enable_feature_id = .migrate_config_program_to_core_bpf,
            .verified_build_hash = null,
        },
    },
    .{
        .program_id = program.address_lookup_table.ID,
        .data = "address_lookup_table_program",
        .enable_feature_id = null,
        .core_bpf_migration_config = .{
            .program_id = program.address_lookup_table.ID,
            .source_buffer_address = program.address_lookup_table.SOURCE_ID,
            .upgrade_authority_address = null,
            .enable_feature_id = .migrate_address_lookup_table_program_to_core_bpf,
            .verified_build_hash = null,
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
        .enable_feature_id = .enable_loader_v4,
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
        .enable_feature_id = .zk_token_sdk_enabled,
        .core_bpf_migration_config = null,
    },
    .{
        .program_id = sig.runtime.program.zk_elgamal.ID,
        .data = "zk_elgamal_proof_program",
        .enable_feature_id = .zk_elgamal_proof_program_enabled,
        .core_bpf_migration_config = null,
    },
};

pub const STATELESS_BUILTINS = [_]StatelessBuiltinPrototype{
    .{
        .program_id = sig.runtime.ids.FEATURE_PROGRAM_ID,
        .core_bpf_migration_config = .{
            .program_id = sig.runtime.ids.FEATURE_PROGRAM_ID,
            .source_buffer_address = sig.runtime.ids.FEATURE_PROGRAM_SOURCE_ID,
            .upgrade_authority_address = null,
            .enable_feature_id = .migrate_feature_gate_program_to_core_bpf,
            .verified_build_hash = .{ .data = .{
                0x19, 0x2e, 0xd7, 0x27, 0x33, 0x4a, 0xbe, 0x82, 0x2d, 0x5a, 0xcc, 0xba, 0x8b, 0x88,
                0x6e, 0x25, 0xf8, 0x8b, 0x03, 0xc7, 0x69, 0x73, 0xc2, 0xe7, 0x29, 0x0c, 0xfb, 0x55,
                0xb9, 0xe1, 0x11, 0x5f,
            } },
        },
    },
};
