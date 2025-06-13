const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

/// `FeatureSet` holds the set of currently active and inactive features
///
/// TODO: add features
///
/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/feature-set/src/lib.rs#L1188
pub const FeatureSet = struct {
    active: std.AutoArrayHashMapUnmanaged(Pubkey, Slot),

    pub const EMPTY: FeatureSet = .{ .active = .{} };

    pub fn deinit(self: FeatureSet, allocator: std.mem.Allocator) void {
        var active_ = self.active;
        active_.deinit(allocator);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/2d834361c096198176dbdc4524d5003bccf6c192/feature-set/src/lib.rs#L51
    pub fn isActive(self: *const FeatureSet, feature: Pubkey) bool {
        return self.active.contains(feature);
    }

    pub fn allEnabled(allocator: std.mem.Allocator) !FeatureSet {
        var feature_set = FeatureSet.EMPTY;
        for (FEATURES) |feature| try feature_set.active.put(allocator, feature, 0);
        return feature_set;
    }
};

pub const DEPRECATE_REWARDS_SYSVAR =
    Pubkey.parseBase58String("GaBtBJvmS4Arjj5W1NmFcyvPjsHN38UGYDq2MDwbs9Qu") catch unreachable;

pub const PICO_INFLATION =
    Pubkey.parseBase58String("4RWNif6C2WCNiKVW7otP4G7dkmkHGyKQWRpuZ1pxKU5m") catch unreachable;

pub const FULL_INFLATION_DEVNET_AND_TESTNET =
    Pubkey.parseBase58String("DT4n6ABDqs6w4bnfwrXT9rsprcPf6cdDga1egctaPkLC") catch unreachable;

pub const FULL_INFLATION_MAINNET_VOTE =
    Pubkey.parseBase58String("BzBBveUDymEYoYzcMWNQCx3cd4jQs7puaVFHLtsbB6fm") catch unreachable;

pub const FULL_INFLATION_MAINNET_ENABLE =
    Pubkey.parseBase58String("7XRJcS5Ud5vxGB54JbK9N2vBZVwnwdBNeJW1ibRgD9gx") catch unreachable;

pub const SECP256R1_FEATURE_ID =
    Pubkey.parseBase58String("sr11RdZWgbHTHxSroPALe6zgaT5A1K9LcE4nfsZS4gi") catch unreachable;

pub const SECP256K1_PROGRAM_ENABLED =
    Pubkey.parseBase58String("E3PHP7w8kB7np3CTQ1qQ2tW3KCtjRSXBQgW9vM2mWv2Y") catch unreachable;

pub const SPL_TOKEN_V2_MULTISIG_FIX =
    Pubkey.parseBase58String("E5JiFDQCwyC6QfT9REFyMpfK2mHcmv1GUDySU1Ue7TYv") catch unreachable;

pub const NO_OVERFLOW_RENT_DISTRIBUTION =
    Pubkey.parseBase58String("4kpdyrcj5jS47CZb2oJGfVxjYbsMm2Kx97gFyZrxxwXz") catch unreachable;

pub const FILTER_STAKE_DELEGATION_ACCOUNTS =
    Pubkey.parseBase58String("GE7fRxmW46K6EmCD9AMZSbnaJ2e3LfqCZzdHi9hmYAgi") catch unreachable;

pub const REQUIRE_CUSTODIAN_FOR_LOCKED_STAKE_AUTHORIZE =
    Pubkey.parseBase58String("D4jsDcXaqdW8tDAWn8H4R25Cdns2YwLneujSL1zvjW6R") catch unreachable;

pub const SPL_TOKEN_V2_SELF_TRANSFER_FIX =
    Pubkey.parseBase58String("BL99GYhdjjcv6ys22C9wPgn2aTVERDbPHHo4NbS3hgp7") catch unreachable;

pub const WARP_TIMESTAMP_AGAIN =
    Pubkey.parseBase58String("GvDsGDkH5gyzwpDhxNixx8vtx1kwYHH13RiNAPw27zXb") catch unreachable;

pub const CHECK_INIT_VOTE_DATA =
    Pubkey.parseBase58String("3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F") catch unreachable;

pub const SECP256K1_RECOVER_SYSCALL_ENABLED =
    Pubkey.parseBase58String("6RvdSWHh8oh72Dp7wMTS2DBkf3fRPtChfNrAo3cZZoXJ") catch unreachable;

pub const SYSTEM_TRANSFER_ZERO_CHECK =
    Pubkey.parseBase58String("BrTR9hzw4WBGFP65AJMbpAo64DcA3U6jdPSga9fMV5cS") catch unreachable;

pub const BLAKE3_SYSCALL_ENABLED =
    Pubkey.parseBase58String("HTW2pSyErTj4BV6KBM9NZ9VBUJVxt7sacNWcf76wtzb3") catch unreachable;

pub const DEDUPE_CONFIG_PROGRAM_SIGNERS =
    Pubkey.parseBase58String("8kEuAshXLsgkUEdcFVLqrjCGGHVWFW99ZZpxvAzzMtBp") catch unreachable;

pub const VERIFY_TX_SIGNATURES_LEN =
    Pubkey.parseBase58String("EVW9B5xD9FFK7vw1SBARwMA4s5eRo5eKJdKpsBikzKBz") catch unreachable;

pub const VOTE_STAKE_CHECKED_INSTRUCTIONS =
    Pubkey.parseBase58String("BcWknVcgvonN8sL4HE4XFuEVgfcee5MwxWPAgP6ZV89X") catch unreachable;

pub const RENT_FOR_SYSVARS =
    Pubkey.parseBase58String("BKCPBQQBZqggVnFso5nQ8rQ4RwwogYwjuUt9biBjxwNF") catch unreachable;

pub const LIBSECP256K1_0_5_UPGRADE_ENABLED =
    Pubkey.parseBase58String("DhsYfRjxfnh2g7HKJYSzT79r74Afa1wbHkAgHndrA1oy") catch unreachable;

pub const TX_WIDE_COMPUTE_CAP =
    Pubkey.parseBase58String("5ekBxc8itEnPv4NzGJtr8BVVQLNMQuLMNQQj7pHoLNZ9") catch unreachable;

pub const SPL_TOKEN_V2_SET_AUTHORITY_FIX =
    Pubkey.parseBase58String("FToKNBYyiF4ky9s8WsmLBXHCht17Ek7RXaLZGHzzQhJ1") catch unreachable;

pub const MERGE_NONCE_ERROR_INTO_SYSTEM_ERROR =
    Pubkey.parseBase58String("21AWDosvp3pBamFW91KB35pNoaoZVTM7ess8nr2nt53B") catch unreachable;

pub const DISABLE_FEES_SYSVAR =
    Pubkey.parseBase58String("JAN1trEUEtZjgXYzNBYHU9DYd7GnThhXfFP7SzPXkPsG") catch unreachable;

pub const STAKE_MERGE_WITH_UNMATCHED_CREDITS_OBSERVED =
    Pubkey.parseBase58String("meRgp4ArRPhD3KtCY9c5yAf2med7mBLsjKTPeVUHqBL") catch unreachable;

pub const ZK_TOKEN_SDK_ENABLED =
    Pubkey.parseBase58String("zk1snxsc6Fh3wsGNbbHAJNHiJoYgF29mMnTSusGx5EJ") catch unreachable;

pub const CURVE25519_SYSCALL_ENABLED =
    Pubkey.parseBase58String("7rcw5UtqgDTBBv2EcynNfYckgdAaH1MAsCjKgXMkN7Ri") catch unreachable;

pub const CURVE25519_RESTRICT_MSM_LENGTH =
    Pubkey.parseBase58String("eca6zf6JJRjQsYYPkBHF3N32MTzur4n2WL4QiiacPCL") catch unreachable;

pub const VERSIONED_TX_MESSAGE_ENABLED =
    Pubkey.parseBase58String("3KZZ6Ks1885aGBQ45fwRcPXVBCtzUvxhUTkwKMR41Tca") catch unreachable;

pub const LIBSECP256K1_FAIL_ON_BAD_COUNT =
    Pubkey.parseBase58String("8aXvSuopd1PUj7UhehfXJRg6619RHp8ZvwTyyJHdUYsj") catch unreachable;

pub const LIBSECP256K1_FAIL_ON_BAD_COUNT2 =
    Pubkey.parseBase58String("54KAoNiUERNoWWUhTWWwXgym94gzoXFVnHyQwPA18V9A") catch unreachable;

pub const INSTRUCTIONS_SYSVAR_OWNED_BY_SYSVAR =
    Pubkey.parseBase58String("H3kBSaKdeiUsyHmeHqjJYNc27jesXZ6zWj3zWkowQbkV") catch unreachable;

pub const STAKE_PROGRAM_ADVANCE_ACTIVATING_CREDITS_OBSERVED =
    Pubkey.parseBase58String("SAdVFw3RZvzbo6DvySbSdBnHN4gkzSTH9dSxesyKKPj") catch unreachable;

pub const CREDITS_AUTO_REWIND =
    Pubkey.parseBase58String("BUS12ciZ5gCoFafUHWW8qaFMMtwFQGVxjsDheWLdqBE2") catch unreachable;

pub const DEMOTE_PROGRAM_WRITE_LOCKS =
    Pubkey.parseBase58String("3E3jV7v9VcdJL8iYZUMax9DiDno8j7EWUVbhm9RtShj2") catch unreachable;

pub const ED25519_PROGRAM_ENABLED =
    Pubkey.parseBase58String("6ppMXNYLhVd7GcsZ5uV11wQEW7spppiMVfqQv5SXhDpX") catch unreachable;

pub const RETURN_DATA_SYSCALL_ENABLED =
    Pubkey.parseBase58String("DwScAzPUjuv65TMbDnFY7AgwmotzWy3xpEJMXM3hZFaB") catch unreachable;

pub const REDUCE_REQUIRED_DEPLOY_BALANCE =
    Pubkey.parseBase58String("EBeznQDjcPG8491sFsKZYBi5S5jTVXMpAKNDJMQPS2kq") catch unreachable;

pub const SOL_LOG_DATA_SYSCALL_ENABLED =
    Pubkey.parseBase58String("6uaHcKPGUy4J7emLBgUTeufhJdiwhngW6a1R9B7c2ob9") catch unreachable;

pub const STAKES_REMOVE_DELEGATION_IF_INACTIVE =
    Pubkey.parseBase58String("HFpdDDNQjvcXnXKec697HDDsyk6tFoWS2o8fkxuhQZpL") catch unreachable;

pub const DO_SUPPORT_REALLOC =
    Pubkey.parseBase58String("75m6ysz33AfLA5DDEzWM1obBrnPQRSsdVQ2nRmc8Vuu1") catch unreachable;

pub const PREVENT_CALLING_PRECOMPILES_AS_PROGRAMS =
    Pubkey.parseBase58String("4ApgRX3ud6p7LNMJmsuaAcZY5HWctGPr5obAsjB3A54d") catch unreachable;

pub const OPTIMIZE_EPOCH_BOUNDARY_UPDATES =
    Pubkey.parseBase58String("265hPS8k8xJ37ot82KEgjRunsUp5w4n4Q4VwwiN9i9ps") catch unreachable;

pub const REMOVE_NATIVE_LOADER =
    Pubkey.parseBase58String("HTTgmruMYRZEntyL3EdCDdnS6e4D5wRq1FA7kQsb66qq") catch unreachable;

pub const SEND_TO_TPU_VOTE_PORT =
    Pubkey.parseBase58String("C5fh68nJ7uyKAuYZg2x9sEQ5YrVf3dkW6oojNBSc3Jvo") catch unreachable;

pub const REQUESTABLE_HEAP_SIZE =
    Pubkey.parseBase58String("CCu4boMmfLuqcmfTLPHQiUo22ZdUsXjgzPAURYaWt1Bw") catch unreachable;

pub const DISABLE_FEE_CALCULATOR =
    Pubkey.parseBase58String("2jXx2yDmGysmBKfKYNgLj2DQyAQv6mMk2BPh4eSbyB4H") catch unreachable;

pub const ADD_COMPUTE_BUDGET_PROGRAM =
    Pubkey.parseBase58String("4d5AKtxoh93Dwm1vHXUU3iRATuMndx1c431KgT2td52r") catch unreachable;

pub const NONCE_MUST_BE_WRITABLE =
    Pubkey.parseBase58String("BiCU7M5w8ZCMykVSyhZ7Q3m2SWoR2qrEQ86ERcDX77ME") catch unreachable;

pub const SPL_TOKEN_V3_3_0_RELEASE =
    Pubkey.parseBase58String("Ftok2jhqAqxUWEiCVRrfRs9DPppWP8cgTB7NQNKL88mS") catch unreachable;

pub const LEAVE_NONCE_ON_SUCCESS =
    Pubkey.parseBase58String("E8MkiWZNNPGU6n55jkGzyj8ghUmjCHRmDFdYYFYHxWhQ") catch unreachable;

pub const REJECT_EMPTY_INSTRUCTION_WITHOUT_PROGRAM =
    Pubkey.parseBase58String("9kdtFSrXHQg3hKkbXkQ6trJ3Ja1xpJ22CTFSNAciEwmL") catch unreachable;

pub const FIXED_MEMCPY_NONOVERLAPPING_CHECK =
    Pubkey.parseBase58String("36PRUK2Dz6HWYdG9SpjeAsF5F3KxnFCakA2BZMbtMhSb") catch unreachable;

pub const REJECT_NON_RENT_EXEMPT_VOTE_WITHDRAWS =
    Pubkey.parseBase58String("7txXZZD6Um59YoLMF7XUNimbMjsqsWhc7g2EniiTrmp1") catch unreachable;

pub const EVICT_INVALID_STAKES_CACHE_ENTRIES =
    Pubkey.parseBase58String("EMX9Q7TVFAmQ9V1CggAkhMzhXSg8ECp7fHrWQX2G1chf") catch unreachable;

pub const ALLOW_VOTES_TO_DIRECTLY_UPDATE_VOTE_STATE =
    Pubkey.parseBase58String("Ff8b1fBeB86q8cjq47ZhsQLgv5EkHu3G1C99zjUfAzrq") catch unreachable;

pub const MAX_TX_ACCOUNT_LOCKS =
    Pubkey.parseBase58String("CBkDroRDqm8HwHe6ak9cguPjUomrASEkfmxEaZ5CNNxz") catch unreachable;

pub const REQUIRE_RENT_EXEMPT_ACCOUNTS =
    Pubkey.parseBase58String("BkFDxiJQWZXGTZaJQxH7wVEHkAmwCgSEVkrvswFfRJPD") catch unreachable;

pub const FILTER_VOTES_OUTSIDE_SLOT_HASHES =
    Pubkey.parseBase58String("3gtZPqvPpsbXZVCx6hceMfWxtsmrjMzmg8C7PLKSxS2d") catch unreachable;

pub const UPDATE_SYSCALL_BASE_COSTS =
    Pubkey.parseBase58String("2h63t332mGCCsWK2nqqqHhN4U9ayyqhLVFvczznHDoTZ") catch unreachable;

pub const STAKE_DEACTIVATE_DELINQUENT_INSTRUCTION =
    Pubkey.parseBase58String("437r62HoAdUb63amq3D7ENnBLDhHT2xY8eFkLJYVKK4x") catch unreachable;

pub const VOTE_WITHDRAW_AUTHORITY_MAY_CHANGE_AUTHORIZED_VOTER =
    Pubkey.parseBase58String("AVZS3ZsN4gi6Rkx2QUibYuSJG3S6QHib7xCYhG6vGJxU") catch unreachable;

pub const SPL_ASSOCIATED_TOKEN_ACCOUNT_V1_0_4 =
    Pubkey.parseBase58String("FaTa4SpiaSNH44PGC4z8bnGVTkSRYaWvrBs3KTu8XQQq") catch unreachable;

pub const REJECT_VOTE_ACCOUNT_CLOSE_UNLESS_ZERO_CREDIT_EPOCH =
    Pubkey.parseBase58String("ALBk3EWdeAg2WAGf6GPDUf1nynyNqCdEVmgouG7rpuCj") catch unreachable;

pub const ADD_GET_PROCESSED_SIBLING_INSTRUCTION_SYSCALL =
    Pubkey.parseBase58String("CFK1hRCNy8JJuAAY8Pb2GjLFNdCThS2qwZNe3izzBMgn") catch unreachable;

pub const BANK_TRANSACTION_COUNT_FIX =
    Pubkey.parseBase58String("Vo5siZ442SaZBKPXNocthiXysNviW4UYPwRFggmbgAp") catch unreachable;

pub const DISABLE_BPF_DEPRECATED_LOAD_INSTRUCTIONS =
    Pubkey.parseBase58String("3XgNukcZWf9o3HdA3fpJbm94XFc4qpvTXc8h1wxYwiPi") catch unreachable;

pub const DISABLE_BPF_UNRESOLVED_SYMBOLS_AT_RUNTIME =
    Pubkey.parseBase58String("4yuaYAj2jGMGTh1sSmi4G2eFscsDq8qjugJXZoBN6YEa") catch unreachable;

pub const RECORD_INSTRUCTION_IN_TRANSACTION_CONTEXT_PUSH =
    Pubkey.parseBase58String("3aJdcZqxoLpSBxgeYGjPwaYS1zzcByxUDqJkbzWAH1Zb") catch unreachable;

pub const SYSCALL_SATURATED_MATH =
    Pubkey.parseBase58String("HyrbKftCdJ5CrUfEti6x26Cj7rZLNe32weugk7tLcWb8") catch unreachable;

pub const CHECK_PHYSICAL_OVERLAPPING =
    Pubkey.parseBase58String("nWBqjr3gpETbiaVj3CBJ3HFC5TMdnJDGt21hnvSTvVZ") catch unreachable;

pub const LIMIT_SECP256K1_RECOVERY_ID =
    Pubkey.parseBase58String("7g9EUwj4j7CS21Yx1wvgWLjSZeh5aPq8x9kpoPwXM8n8") catch unreachable;

pub const DISABLE_DEPRECATED_LOADER =
    Pubkey.parseBase58String("GTUMCZ8LTNxVfxdrw7ZsDFTxXb7TutYkzJnFwinpE6dg") catch unreachable;

pub const CHECK_SLICE_TRANSLATION_SIZE =
    Pubkey.parseBase58String("GmC19j9qLn2RFk5NduX6QXaDhVpGncVVBzyM8e9WMz2F") catch unreachable;

pub const STAKE_SPLIT_USES_RENT_SYSVAR =
    Pubkey.parseBase58String("FQnc7U4koHqWgRvFaBJjZnV8VPg6L6wWK33yJeDp4yvV") catch unreachable;

pub const ADD_GET_MINIMUM_DELEGATION_INSTRUCTION_TO_STAKE_PROGRAM =
    Pubkey.parseBase58String("St8k9dVXP97xT6faW24YmRSYConLbhsMJA4TJTBLmMT") catch unreachable;

pub const ERROR_ON_SYSCALL_BPF_FUNCTION_HASH_COLLISIONS =
    Pubkey.parseBase58String("8199Q2gMD2kwgfopK5qqVWuDbegLgpuFUFHCcUJQDN8b") catch unreachable;

pub const REJECT_CALLX_R10 =
    Pubkey.parseBase58String("3NKRSwpySNwD3TvP5pHnRmkAQRsdkXWRr1WaQh8p4PWX") catch unreachable;

pub const DROP_REDUNDANT_TURBINE_PATH =
    Pubkey.parseBase58String("4Di3y24QFLt5QEUPZtbnjyfQKfm6ZMTfa6Dw1psfoMKU") catch unreachable;

pub const EXECUTABLES_INCUR_CPI_DATA_COST =
    Pubkey.parseBase58String("7GUcYgq4tVtaqNCKT3dho9r4665Qp5TxCZ27Qgjx3829") catch unreachable;

pub const FIX_RECENT_BLOCKHASHES =
    Pubkey.parseBase58String("6iyggb5MTcsvdcugX7bEKbHV8c6jdLbpHwkncrgLMhfo") catch unreachable;

pub const UPDATE_REWARDS_FROM_CACHED_ACCOUNTS =
    Pubkey.parseBase58String("28s7i3htzhahXQKqmS2ExzbEoUypg9krwvtK2M9UWXh9") catch unreachable;

pub const ENABLE_PARTITIONED_EPOCH_REWARD =
    Pubkey.parseBase58String("9bn2vTJUsUcnpiZWbu2woSKtTGW3ErZC9ERv88SDqQjK") catch unreachable;

pub const PARTITIONED_EPOCH_REWARDS_SUPERFEATURE =
    Pubkey.parseBase58String("PERzQrt5gBD1XEe2c9XdFWqwgHY3mr7cYWbm5V772V8") catch unreachable;

pub const SPL_TOKEN_V3_4_0 =
    Pubkey.parseBase58String("Ftok4njE8b7tDffYkC5bAbCaQv5sL6jispYrprzatUwN") catch unreachable;

pub const SPL_ASSOCIATED_TOKEN_ACCOUNT_V1_1_0 =
    Pubkey.parseBase58String("FaTa17gVKoqbh38HcfiQonPsAaQViyDCCSg71AubYZw8") catch unreachable;

pub const DEFAULT_UNITS_PER_INSTRUCTION =
    Pubkey.parseBase58String("J2QdYx8crLbTVK8nur1jeLsmc3krDbfjoxoea2V1Uy5Q") catch unreachable;

pub const STAKE_ALLOW_ZERO_UNDELEGATED_AMOUNT =
    Pubkey.parseBase58String("sTKz343FM8mqtyGvYWvbLpTThw3ixRM4Xk8QvZ985mw") catch unreachable;

pub const REQUIRE_STATIC_PROGRAM_IDS_IN_TRANSACTION =
    Pubkey.parseBase58String("8FdwgyHFEjhAdjWfV2vfqk7wA1g9X3fQpKH7SBpEv3kC") catch unreachable;

pub const STAKE_RAISE_MINIMUM_DELEGATION_TO_1_SOL =
    Pubkey.parseBase58String("9onWzzvCzNC2jfhxxeqRgs5q7nFAAKpCUvkj6T6GJK9i") catch unreachable;

pub const STAKE_MINIMUM_DELEGATION_FOR_REWARDS =
    Pubkey.parseBase58String("G6ANXD6ptCSyNd9znZm7j4dEczAJCfx7Cy43oBx3rKHJ") catch unreachable;

pub const ADD_SET_COMPUTE_UNIT_PRICE_IX =
    Pubkey.parseBase58String("98std1NSHqXi9WYvFShfVepRdCoq1qvsp8fsR2XZtG8g") catch unreachable;

pub const DISABLE_DEPLOY_OF_ALLOC_FREE_SYSCALL =
    Pubkey.parseBase58String("79HWsX9rpnnJBPcdNURVqygpMAfxdrAirzAGAVmf92im") catch unreachable;

pub const INCLUDE_ACCOUNT_INDEX_IN_RENT_ERROR =
    Pubkey.parseBase58String("2R72wpcQ7qV7aTJWUumdn8u5wmmTyXbK7qzEy7YSAgyY") catch unreachable;

pub const ADD_SHRED_TYPE_TO_SHRED_SEED =
    Pubkey.parseBase58String("Ds87KVeqhbv7Jw8W6avsS1mqz3Mw5J3pRTpPoDQ2QdiJ") catch unreachable;

pub const WARP_TIMESTAMP_WITH_A_VENGEANCE =
    Pubkey.parseBase58String("3BX6SBeEBibHaVQXywdkcgyUk6evfYZkHdztXiDtEpFS") catch unreachable;

pub const SEPARATE_NONCE_FROM_BLOCKHASH =
    Pubkey.parseBase58String("Gea3ZkK2N4pHuVZVxWcnAtS6UEDdyumdYt4pFcKjA3ar") catch unreachable;

pub const ENABLE_DURABLE_NONCE =
    Pubkey.parseBase58String("4EJQtF2pkRyawwcTVfQutzq4Sa5hRhibF6QAK1QXhtEX") catch unreachable;

pub const VOTE_STATE_UPDATE_CREDIT_PER_DEQUEUE =
    Pubkey.parseBase58String("CveezY6FDLVBToHDcvJRmtMouqzsmj4UXYh5ths5G5Uv") catch unreachable;

pub const QUICK_BAIL_ON_PANIC =
    Pubkey.parseBase58String("DpJREPyuMZ5nDfU6H3WTqSqUFSXAfw8u7xqmWtEwJDcP") catch unreachable;

pub const NONCE_MUST_BE_AUTHORIZED =
    Pubkey.parseBase58String("HxrEu1gXuH7iD3Puua1ohd5n4iUKJyFNtNxk9DVJkvgr") catch unreachable;

pub const NONCE_MUST_BE_ADVANCEABLE =
    Pubkey.parseBase58String("3u3Er5Vc2jVcwz4xr2GJeSAXT3fAj6ADHZ4BJMZiScFd") catch unreachable;

pub const VOTE_AUTHORIZE_WITH_SEED =
    Pubkey.parseBase58String("6tRxEYKuy2L5nnv5bgn7iT28MxUbYxp5h7F3Ncf1exrT") catch unreachable;

pub const PRESERVE_RENT_EPOCH_FOR_RENT_EXEMPT_ACCOUNTS =
    Pubkey.parseBase58String("HH3MUYReL2BvqqA3oEcAa7txju5GY6G4nxJ51zvsEjEZ") catch unreachable;

pub const ENABLE_BPF_LOADER_EXTEND_PROGRAM_IX =
    Pubkey.parseBase58String("8Zs9W7D9MpSEtUWSQdGniZk2cNmV22y6FLJwCx53asme") catch unreachable;

pub const ENABLE_EARLY_VERIFICATION_OF_ACCOUNT_MODIFICATIONS =
    Pubkey.parseBase58String("7Vced912WrRnfjaiKRiNBcbuFw7RrnLv3E3z95Y4GTNc") catch unreachable;

pub const SKIP_RENT_REWRITES =
    Pubkey.parseBase58String("CGB2jM8pwZkeeiXQ66kBMyBR6Np61mggL7XUsmLjVcrw") catch unreachable;

pub const PREVENT_CREDITING_ACCOUNTS_THAT_END_RENT_PAYING =
    Pubkey.parseBase58String("812kqX67odAp5NFwM8D2N24cku7WTm9CHUTFUXaDkWPn") catch unreachable;

pub const CAP_BPF_PROGRAM_INSTRUCTION_ACCOUNTS =
    Pubkey.parseBase58String("9k5ijzTbYPtjzu8wj2ErH9v45xecHzQ1x4PMYMMxFgdM") catch unreachable;

pub const LOOSEN_CPI_SIZE_RESTRICTION =
    Pubkey.parseBase58String("GDH5TVdbTPUpRnXaRyQqiKUa7uZAbZ28Q2N9bhbKoMLm") catch unreachable;

pub const USE_DEFAULT_UNITS_IN_FEE_CALCULATION =
    Pubkey.parseBase58String("8sKQrMQoUHtQSUP83SPG4ta2JDjSAiWs7t5aJ9uEd6To") catch unreachable;

pub const COMPACT_VOTE_STATE_UPDATES =
    Pubkey.parseBase58String("86HpNqzutEZwLcPxS6EHDcMNYWk6ikhteg9un7Y2PBKE") catch unreachable;

pub const INCREMENTAL_SNAPSHOT_ONLY_INCREMENTAL_HASH_CALCULATION =
    Pubkey.parseBase58String("25vqsfjk7Nv1prsQJmA4Xu1bN61s8LXCBGUPp8Rfy1UF") catch unreachable;

pub const DISABLE_CPI_SETTING_EXECUTABLE_AND_RENT_EPOCH =
    Pubkey.parseBase58String("B9cdB55u4jQsDNsdTK525yE9dmSc5Ga7YBaBrDFvEhM9") catch unreachable;

pub const ON_LOAD_PRESERVE_RENT_EPOCH_FOR_RENT_EXEMPT_ACCOUNTS =
    Pubkey.parseBase58String("CpkdQmspsaZZ8FVAouQTtTWZkc8eeQ7V3uj7dWz543rZ") catch unreachable;

pub const ACCOUNT_HASH_IGNORE_SLOT =
    Pubkey.parseBase58String("SVn36yVApPLYsa8koK3qUcy14zXDnqkNYWyUh1f4oK1") catch unreachable;

pub const SET_EXEMPT_RENT_EPOCH_MAX =
    Pubkey.parseBase58String("5wAGiy15X1Jb2hkHnPDCM8oB9V42VNA9ftNVFK84dEgv") catch unreachable;

pub const RELAX_AUTHORITY_SIGNER_CHECK_FOR_LOOKUP_TABLE_CREATION =
    Pubkey.parseBase58String("FKAcEvNgSY79RpqsPNUV5gDyumopH4cEHqUxyfm8b8Ap") catch unreachable;

pub const STOP_SIBLING_INSTRUCTION_SEARCH_AT_PARENT =
    Pubkey.parseBase58String("EYVpEP7uzH1CoXzbD6PubGhYmnxRXPeq3PPsm1ba3gpo") catch unreachable;

pub const VOTE_STATE_UPDATE_ROOT_FIX =
    Pubkey.parseBase58String("G74BkWBzmsByZ1kxHy44H3wjwp5hp7JbrGRuDpco22tY") catch unreachable;

pub const CAP_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION =
    Pubkey.parseBase58String("9gxu85LYRAcZL38We8MYJ4A9AwgBBPtVBAqebMcT1241") catch unreachable;

pub const EPOCH_ACCOUNTS_HASH =
    Pubkey.parseBase58String("5GpmAKxaGsWWbPp4bNXFLJxZVvG92ctxf7jQnzTQjF3n") catch unreachable;

pub const REMOVE_DEPRECATED_REQUEST_UNIT_IX =
    Pubkey.parseBase58String("EfhYd3SafzGT472tYQDUc4dPd2xdEfKs5fwkowUgVt4W") catch unreachable;

pub const DISABLE_REHASH_FOR_RENT_EPOCH =
    Pubkey.parseBase58String("DTVTkmw3JSofd8CJVJte8PXEbxNQ2yZijvVr3pe2APPj") catch unreachable;

pub const INCREASE_TX_ACCOUNT_LOCK_LIMIT =
    Pubkey.parseBase58String("9LZdXeKGeBV6hRLdxS1rHbHoEUsKqesCC2ZAPTPKJAbK") catch unreachable;

pub const LIMIT_MAX_INSTRUCTION_TRACE_LENGTH =
    Pubkey.parseBase58String("GQALDaC48fEhZGWRj9iL5Q889emJKcj3aCvHF7VCbbF4") catch unreachable;

pub const CHECK_SYSCALL_OUTPUTS_DO_NOT_OVERLAP =
    Pubkey.parseBase58String("3uRVPBpyEJRo1emLCrq38eLRFGcu6uKSpUXqGvU8T7SZ") catch unreachable;

pub const ENABLE_BPF_LOADER_SET_AUTHORITY_CHECKED_IX =
    Pubkey.parseBase58String("5x3825XS7M2A3Ekbn5VGGkvFoAg5qrRWkTrY4bARP1GL") catch unreachable;

pub const ENABLE_ALT_BN128_SYSCALL =
    Pubkey.parseBase58String("A16q37opZdQMCbe5qJ6xpBB9usykfv8jZaMkxvZQi4GJ") catch unreachable;

pub const SIMPLIFY_ALT_BN128_SYSCALL_ERROR_CODES =
    Pubkey.parseBase58String("JDn5q3GBeqzvUa7z67BbmVHVdE3EbUAjvFep3weR3jxX") catch unreachable;

pub const ENABLE_ALT_BN128_COMPRESSION_SYSCALL =
    Pubkey.parseBase58String("EJJewYSddEEtSZHiqugnvhQHiWyZKjkFDQASd7oKSagn") catch unreachable;

pub const FIX_ALT_BN128_MULTIPLICATION_INPUT_LENGTH =
    Pubkey.parseBase58String("bn2puAyxUx6JUabAxYdKdJ5QHbNNmKw8dCGuGCyRrFN") catch unreachable;

pub const ENABLE_PROGRAM_REDEPLOYMENT_COOLDOWN =
    Pubkey.parseBase58String("J4HFT8usBxpcF63y46t1upYobJgChmKyZPm5uTBRg25Z") catch unreachable;

pub const COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH =
    Pubkey.parseBase58String("noRuG2kzACwgaY7TVmLRnUNPLKNVQE1fb7X55YWBehp") catch unreachable;

pub const ENABLE_TURBINE_FANOUT_EXPERIMENTS =
    Pubkey.parseBase58String("D31EFnLgdiysi84Woo3of4JMu7VmasUS3Z7j9HYXCeLY") catch unreachable;

pub const DISABLE_TURBINE_FANOUT_EXPERIMENTS =
    Pubkey.parseBase58String("Gz1aLrbeQ4Q6PTSafCZcGWZXz91yVRi7ASFzFEr1U4sa") catch unreachable;

pub const MOVE_SERIALIZED_LEN_PTR_IN_CPI =
    Pubkey.parseBase58String("74CoWuBmt3rUVUrCb2JiSTvh6nXyBWUsK4SaMj3CtE3T") catch unreachable;

pub const UPDATE_HASHES_PER_TICK =
    Pubkey.parseBase58String("3uFHb9oKdGfgZGJK9EHaAXN4USvnQtAFC13Fh5gGFS5B") catch unreachable;

pub const ENABLE_BIG_MOD_EXP_SYSCALL =
    Pubkey.parseBase58String("EBq48m8irRKuE7ZnMTLvLg2UuGSqhe8s8oMqnmja1fJw") catch unreachable;

pub const DISABLE_BUILTIN_LOADER_OWNERSHIP_CHAINS =
    Pubkey.parseBase58String("4UDcAfQ6EcA6bdcadkeHpkarkhZGJ7Bpq7wTAiRMjkoi") catch unreachable;

pub const CAP_TRANSACTION_ACCOUNTS_DATA_SIZE =
    Pubkey.parseBase58String("DdLwVYuvDz26JohmgSbA7mjpJFgX5zP2dkp8qsF2C33V") catch unreachable;

pub const REMOVE_CONGESTION_MULTIPLIER_FROM_FEE_CALCULATION =
    Pubkey.parseBase58String("A8xyMHZovGXFkorFqEmVH2PKGLiBip5JD7jt4zsUWo4H") catch unreachable;

pub const ENABLE_REQUEST_HEAP_FRAME_IX =
    Pubkey.parseBase58String("Hr1nUA9b7NJ6eChS26o7Vi8gYYDDwWD3YeBfzJkTbU86") catch unreachable;

pub const PREVENT_RENT_PAYING_RENT_RECIPIENTS =
    Pubkey.parseBase58String("Fab5oP3DmsLYCiQZXdjyqT3ukFFPrsmqhXU4WU1AWVVF") catch unreachable;

pub const DELAY_VISIBILITY_OF_PROGRAM_DEPLOYMENT =
    Pubkey.parseBase58String("GmuBvtFb2aHfSfMXpuFeWZGHyDeCLPS79s48fmCWCfM5") catch unreachable;

pub const APPLY_COST_TRACKER_DURING_REPLAY =
    Pubkey.parseBase58String("2ry7ygxiYURULZCrypHhveanvP5tzZ4toRwVp89oCNSj") catch unreachable;

pub const BPF_ACCOUNT_DATA_DIRECT_MAPPING =
    Pubkey.parseBase58String("AjX3A4Nv2rzUuATEUWLP4rrBaBropyUnHxEvFDj1dKbx") catch unreachable;

pub const ADD_SET_TX_LOADED_ACCOUNTS_DATA_SIZE_INSTRUCTION =
    Pubkey.parseBase58String("G6vbf1UBok8MWb8m25ex86aoQHeKTzDKzuZADHkShqm6") catch unreachable;

pub const SWITCH_TO_NEW_ELF_PARSER =
    Pubkey.parseBase58String("Cdkc8PPTeTNUPoZEfCY5AyetUrEdkZtNPMgz58nqyaHD") catch unreachable;

pub const ROUND_UP_HEAP_SIZE =
    Pubkey.parseBase58String("CE2et8pqgyQMP2mQRg3CgvX8nJBKUArMu3wfiQiQKY1y") catch unreachable;

pub const REMOVE_BPF_LOADER_INCORRECT_PROGRAM_ID =
    Pubkey.parseBase58String("2HmTkCj9tXuPE4ueHzdD7jPeMf9JGCoZh5AsyoATiWEe") catch unreachable;

pub const INCLUDE_LOADED_ACCOUNTS_DATA_SIZE_IN_FEE_CALCULATION =
    Pubkey.parseBase58String("EaQpmC6GtRssaZ3PCUM5YksGqUdMLeZ46BQXYtHYakDS") catch unreachable;

pub const NATIVE_PROGRAMS_CONSUME_CU =
    Pubkey.parseBase58String("8pgXCMNXC8qyEFypuwpXyRxLXZdpM4Qo72gJ6k87A6wL") catch unreachable;

pub const SIMPLIFY_WRITABLE_PROGRAM_ACCOUNT_CHECK =
    Pubkey.parseBase58String("5ZCcFAzJ1zsFKe1KSZa9K92jhx7gkcKj97ci2DBo1vwj") catch unreachable;

pub const STOP_TRUNCATING_STRINGS_IN_SYSCALLS =
    Pubkey.parseBase58String("16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg") catch unreachable;

pub const CLEAN_UP_DELEGATION_ERRORS =
    Pubkey.parseBase58String("Bj2jmUsM2iRhfdLLDSTkhM5UQRQvQHm57HSmPibPtEyu") catch unreachable;

pub const VOTE_STATE_ADD_VOTE_LATENCY =
    Pubkey.parseBase58String("7axKe5BTYBDD87ftzWbk5DfzWMGyRvqmWTduuo22Yaqy") catch unreachable;

pub const CHECKED_ARITHMETIC_IN_FEE_VALIDATION =
    Pubkey.parseBase58String("5Pecy6ie6XGm22pc9d4P9W5c31BugcFBuy6hsP2zkETv") catch unreachable;

pub const LAST_RESTART_SLOT_SYSVAR =
    Pubkey.parseBase58String("HooKD5NC9QNxk25QuzCssB8ecrEzGt6eXEPBUxWp1LaR") catch unreachable;

pub const REDUCE_STAKE_WARMUP_COOLDOWN =
    Pubkey.parseBase58String("GwtDQBghCTBgmX2cpEGNPxTEBUTQRaDMGTr5qychdGMj") catch unreachable;

pub const REVISE_TURBINE_EPOCH_STAKES =
    Pubkey.parseBase58String("BTWmtJC8U5ZLMbBUUA1k6As62sYjPEjAiNAT55xYGdJU") catch unreachable;

pub const ENABLE_POSEIDON_SYSCALL =
    Pubkey.parseBase58String("FL9RsQA6TVUoh5xJQ9d936RHSebA1NLQqe3Zv9sXZRpr") catch unreachable;

pub const TIMELY_VOTE_CREDITS =
    Pubkey.parseBase58String("tvcF6b1TRz353zKuhBjinZkKzjmihXmBAHJdjNYw1sQ") catch unreachable;

pub const REMAINING_COMPUTE_UNITS_SYSCALL_ENABLED =
    Pubkey.parseBase58String("5TuppMutoyzhUSfuYdhgzD47F92GL1g89KpCZQKqedxP") catch unreachable;

pub const ENABLE_LOADER_V4 =
    Pubkey.parseBase58String("8Cb77yHjPWe9wuWUfXeh6iszFGCDGNCoFk3tprViYHNm") catch unreachable;

pub const REQUIRE_RENT_EXEMPT_SPLIT_DESTINATION =
    Pubkey.parseBase58String("D2aip4BBr8NPWtU9vLrwrBvbuaQ8w1zV38zFLxx4pfBV") catch unreachable;

pub const BETTER_ERROR_CODES_FOR_TX_LAMPORT_CHECK =
    Pubkey.parseBase58String("Ffswd3egL3tccB6Rv3XY6oqfdzn913vUcjCSnpvCKpfx") catch unreachable;

pub const UPDATE_HASHES_PER_TICK2 =
    Pubkey.parseBase58String("EWme9uFqfy1ikK1jhJs8fM5hxWnK336QJpbscNtizkTU") catch unreachable;

pub const UPDATE_HASHES_PER_TICK3 =
    Pubkey.parseBase58String("8C8MCtsab5SsfammbzvYz65HHauuUYdbY2DZ4sznH6h5") catch unreachable;

pub const UPDATE_HASHES_PER_TICK4 =
    Pubkey.parseBase58String("8We4E7DPwF2WfAN8tRTtWQNhi98B99Qpuj7JoZ3Aikgg") catch unreachable;

pub const UPDATE_HASHES_PER_TICK5 =
    Pubkey.parseBase58String("BsKLKAn1WM4HVhPRDsjosmqSg2J8Tq5xP2s2daDS6Ni4") catch unreachable;

pub const UPDATE_HASHES_PER_TICK6 =
    Pubkey.parseBase58String("FKu1qYwLQSiehz644H6Si65U5ZQ2cp9GxsyFUfYcuADv") catch unreachable;

pub const VALIDATE_FEE_COLLECTOR_ACCOUNT =
    Pubkey.parseBase58String("prpFrMtgNmzaNzkPJg9o753fVvbHKqNrNTm76foJ2wm") catch unreachable;

pub const DISABLE_RENT_FEES_COLLECTION =
    Pubkey.parseBase58String("CJzY83ggJHqPGDq8VisV3U91jDJLuEaALZooBrXtnnLU") catch unreachable;

pub const ENABLE_ZK_TRANSFER_WITH_FEE =
    Pubkey.parseBase58String("zkNLP7EQALfC1TYeB3biDU7akDckj8iPkvh9y2Mt2K3") catch unreachable;

pub const DROP_LEGACY_SHREDS =
    Pubkey.parseBase58String("GV49KKQdBNaiv2pgqhS2Dy3GWYJGXMTVYbYkdk91orRy") catch unreachable;

pub const ALLOW_COMMISSION_DECREASE_AT_ANY_TIME =
    Pubkey.parseBase58String("decoMktMcnmiq6t3u7g5BfgcQu91nKZr6RvMYf9z1Jb") catch unreachable;

pub const ADD_NEW_RESERVED_ACCOUNT_KEYS =
    Pubkey.parseBase58String("8U4skmMVnF6k2kMvrWbQuRUT3qQSiTYpSjqmhmgfthZu") catch unreachable;

pub const CONSUME_BLOCKSTORE_DUPLICATE_PROOFS =
    Pubkey.parseBase58String("6YsBCejwK96GZCkJ6mkZ4b68oP63z2PLoQmWjC7ggTqZ") catch unreachable;

pub const INDEX_ERASURE_CONFLICT_DUPLICATE_PROOFS =
    Pubkey.parseBase58String("dupPajaLy2SSn8ko42aZz4mHANDNrLe8Nw8VQgFecLa") catch unreachable;

pub const MERKLE_CONFLICT_DUPLICATE_PROOFS =
    Pubkey.parseBase58String("mrkPjRg79B2oK2ZLgd7S3AfEJaX9B6gAF3H9aEykRUS") catch unreachable;

pub const DISABLE_BPF_LOADER_INSTRUCTIONS =
    Pubkey.parseBase58String("7WeS1vfPRgeeoXArLh7879YcB9mgE9ktjPDtajXeWfXn") catch unreachable;

pub const ENABLE_ZK_PROOF_FROM_ACCOUNT =
    Pubkey.parseBase58String("zkiTNuzBKxrCLMKehzuQeKZyLtX2yvFcEKMML8nExU8") catch unreachable;

pub const COST_MODEL_REQUESTED_WRITE_LOCK_COST =
    Pubkey.parseBase58String("wLckV1a64ngtcKPRGU4S4grVTestXjmNjxBjaKZrAcn") catch unreachable;

pub const ENABLE_GOSSIP_DUPLICATE_PROOF_INGESTION =
    Pubkey.parseBase58String("FNKCMBzYUdjhHyPdsKG2LSmdzH8TCHXn3ytj8RNBS4nG") catch unreachable;

pub const CHAINED_MERKLE_CONFLICT_DUPLICATE_PROOFS =
    Pubkey.parseBase58String("chaie9S2zVfuxJKNRGkyTDokLwWxx6kD2ZLsqQHaDD8") catch unreachable;

pub const ENABLE_CHAINED_MERKLE_SHREDS =
    Pubkey.parseBase58String("7uZBkJXJ1HkuP6R3MJfZs7mLwymBcDbKdqbF51ZWLier") catch unreachable;

pub const REMOVE_ROUNDING_IN_FEE_CALCULATION =
    Pubkey.parseBase58String("BtVN7YjDzNE6Dk7kTT7YTDgMNUZTNgiSJgsdzAeTg2jF") catch unreachable;

pub const ENABLE_TOWER_SYNC_IX =
    Pubkey.parseBase58String("tSynMCspg4xFiCj1v3TDb4c7crMR5tSBhLz4sF7rrNA") catch unreachable;

pub const DEPRECATE_UNUSED_LEGACY_VOTE_PLUMBING =
    Pubkey.parseBase58String("6Uf8S75PVh91MYgPQSHnjRAPQq6an5BDv9vomrCwDqLe") catch unreachable;

pub const REWARD_FULL_PRIORITY_FEE =
    Pubkey.parseBase58String("3opE3EzAKnUftUDURkzMgwpNgimBAypW1mNDYH4x4Zg7") catch unreachable;

pub const GET_SYSVAR_SYSCALL_ENABLED =
    Pubkey.parseBase58String("CLCoTADvV64PSrnR6QXty6Fwrt9Xc6EdxSJE4wLRePjq") catch unreachable;

pub const ABORT_ON_INVALID_CURVE =
    Pubkey.parseBase58String("FuS3FPfJDKSNot99ECLXtp3rueq36hMNStJkPJwWodLh") catch unreachable;

pub const MIGRATE_FEATURE_GATE_PROGRAM_TO_CORE_BPF =
    Pubkey.parseBase58String("4eohviozzEeivk1y9UbrnekbAFMDQyJz5JjA9Y6gyvky") catch unreachable;

pub const VOTE_ONLY_FULL_FEC_SETS =
    Pubkey.parseBase58String("ffecLRhhakKSGhMuc6Fz2Lnfq4uT9q3iu9ZsNaPLxPc") catch unreachable;

pub const MIGRATE_CONFIG_PROGRAM_TO_CORE_BPF =
    Pubkey.parseBase58String("2Fr57nzzkLYXW695UdDxDeR5fhnZWSttZeZYemrnpGFV") catch unreachable;

pub const ENABLE_GET_EPOCH_STAKE_SYSCALL =
    Pubkey.parseBase58String("FKe75t4LXxGaQnVHdUKM6DSFifVVraGZ8LyNo7oPwy1Z") catch unreachable;

pub const MIGRATE_ADDRESS_LOOKUP_TABLE_PROGRAM_TO_CORE_BPF =
    Pubkey.parseBase58String("C97eKZygrkU4JxJsZdjgbUY7iQR7rKTr4NyDWo2E5pRm") catch unreachable;

pub const ZK_ELGAMAL_PROOF_PROGRAM_ENABLED =
    Pubkey.parseBase58String("zkhiy5oLowR7HY4zogXjCjeMXyruLqBwSWH21qcFtnv") catch unreachable;

pub const VERIFY_RETRANSMITTER_SIGNATURE =
    Pubkey.parseBase58String("BZ5g4hRbu5hLQQBdPyo2z9icGyJ8Khiyj3QS6dhWijTb") catch unreachable;

pub const MOVE_STAKE_AND_MOVE_LAMPORTS_IXS =
    Pubkey.parseBase58String("7bTK6Jis8Xpfrs8ZoUfiMDPazTcdPcTWheZFJTA5Z6X4") catch unreachable;

pub const ED25519_PRECOMPILE_VERIFY_STRICT =
    Pubkey.parseBase58String("ed9tNscbWLYBooxWA7FE2B5KHWs8A6sxfY8EzezEcoo") catch unreachable;

pub const VOTE_ONLY_RETRANSMITTER_SIGNED_FEC_SETS =
    Pubkey.parseBase58String("RfEcA95xnhuwooVAhUUksEJLZBF7xKCLuqrJoqk4Zph") catch unreachable;

pub const MOVE_PRECOMPILE_VERIFICATION_TO_SVM =
    Pubkey.parseBase58String("9ypxGLzkMxi89eDerRKXWDXe44UY2z4hBig4mDhNq5Dp") catch unreachable;

pub const ENABLE_TRANSACTION_LOADING_FAILURE_FEES =
    Pubkey.parseBase58String("PaymEPK2oqwT9TXAVfadjztH2H6KfLEB9Hhd5Q5frvP") catch unreachable;

pub const ENABLE_TURBINE_EXTENDED_FANOUT_EXPERIMENTS =
    Pubkey.parseBase58String("BZn14Liea52wtBwrXUxTv6vojuTTmfc7XGEDTXrvMD7b") catch unreachable;

pub const DEPRECATE_LEGACY_VOTE_IXS =
    Pubkey.parseBase58String("depVvnQ2UysGrhwdiwU42tCadZL8GcBb1i2GYhMopQv") catch unreachable;

pub const DISABLE_SBPF_V0_EXECUTION =
    Pubkey.parseBase58String("TestFeature11111111111111111111111111111111") catch unreachable;

pub const REENABLE_SBPF_V0_EXECUTION =
    Pubkey.parseBase58String("TestFeature21111111111111111111111111111111") catch unreachable;

pub const ENABLE_SBPF_V1_DEPLOYMENT_AND_EXECUTION =
    Pubkey.parseBase58String("JE86WkYvTrzW8HgNmrHY7dFYpCmSptUpKupbo2AdQ9cG") catch unreachable;

pub const ENABLE_SBPF_V2_DEPLOYMENT_AND_EXECUTION =
    Pubkey.parseBase58String("F6UVKh1ujTEFK3en2SyAL3cdVnqko1FVEXWhmdLRu6WP") catch unreachable;

pub const ENABLE_SBPF_V3_DEPLOYMENT_AND_EXECUTION =
    Pubkey.parseBase58String("C8XZNs1bfzaiT3YDeXZJ7G5swQWQv7tVzDnCxtHvnSpw") catch unreachable;

pub const REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS =
    Pubkey.parseBase58String("FXs1zh47QbNnhXcnB6YiAQoJ4sGB91tKF3UFHLcKT7PM") catch unreachable;

pub const LIFT_CPI_CALLER_RESTRICTION =
    Pubkey.parseBase58String("HcW8ZjBezYYgvcbxNJwqv1t484Y2556qJsfNDWvJGZRH") catch unreachable;

pub const DISABLE_ACCOUNT_LOADER_SPECIAL_CASE =
    Pubkey.parseBase58String("EQUMpNFr7Nacb1sva56xn1aLfBxppEoSBH8RRVdkcD1x") catch unreachable;

pub const ENABLE_SECP256R1_PRECOMPILE =
    Pubkey.parseBase58String("srremy31J5Y25FrAApwVb9kZcfXbusYMMsvTK9aWv5q") catch unreachable;

pub const ACCOUNTS_LT_HASH =
    Pubkey.parseBase58String("LTHasHQX6661DaDD4S6A2TFi6QBuiwXKv66fB1obfHq") catch unreachable;

pub const SNAPSHOTS_LT_HASH =
    Pubkey.parseBase58String("LTsNAP8h1voEVVToMNBNqoiNQex4aqfUrbFhRH3mSQ2") catch unreachable;

pub const REMOVE_ACCOUNTS_DELTA_HASH =
    Pubkey.parseBase58String("LTdLt9Ycbyoipz5fLysCi1NnDnASsZfmJLJXts5ZxZz") catch unreachable;

pub const MIGRATE_STAKE_PROGRAM_TO_CORE_BPF =
    Pubkey.parseBase58String("6M4oQ6eXneVhtLoiAr4yRYQY43eVLjrKbiDZDJc892yk") catch unreachable;

pub const DEPLETE_CU_METER_ON_VM_FAILURE =
    Pubkey.parseBase58String("B7H2caeia4ZFcpE3QcgMqbiWiBtWrdBRBSJ1DY6Ktxbq") catch unreachable;

pub const RESERVE_MINIMAL_CUS_FOR_BUILTIN_INSTRUCTIONS =
    Pubkey.parseBase58String("C9oAhLxDBm3ssWtJx1yBGzPY55r2rArHmN1pbQn6HogH") catch unreachable;

pub const RAISE_BLOCK_LIMITS_TO_50M =
    Pubkey.parseBase58String("5oMCU3JPaFLr8Zr4ct7yFA7jdk6Mw1RmB8K4u9ZbS42z") catch unreachable;

pub const DROP_UNCHAINED_MERKLE_SHREDS =
    Pubkey.parseBase58String("3A9WtMU4aHuryD3VN7SFKdfXto8HStLb1Jj6HjkgfnGL") catch unreachable;

pub const RELAX_INTRABATCH_ACCOUNT_LOCKS =
    Pubkey.parseBase58String("EbAhnReKK8Sf88CvAfAXbgKji8DV48rsp4q2sgHqgWef") catch unreachable;

pub const CREATE_SLASHING_PROGRAM =
    Pubkey.parseBase58String("sProgVaNWkYdP2eTRAy1CPrgb3b9p8yXCASrPEqo6VJ") catch unreachable;

pub const DISABLE_PARTITIONED_RENT_COLLECTION =
    Pubkey.parseBase58String("2B2SBNbUcr438LtGXNcJNBP2GBSxjx81F945SdSkUSfC") catch unreachable;

pub const ENABLE_VOTE_ADDRESS_LEADER_SCHEDULE =
    Pubkey.parseBase58String("5JsG4NWH8Jbrqdd8uL6BNwnyZK3dQSoieRXG5vmofj9y") catch unreachable;

pub const REQUIRE_STATIC_NONCE_ACCOUNT =
    Pubkey.parseBase58String("7VVhpg5oAjAmnmz1zCcSHb2Z9ecZB2FQqpnEwReka9Zm") catch unreachable;

pub const RAISE_BLOCK_LIMITS_TO_60M =
    Pubkey.parseBase58String("6oMCUgfY6BzZ6jwB681J6ju5Bh6CjVXbd7NeWYqiXBSu") catch unreachable;

pub const MASK_OUT_RENT_EPOCH_IN_VM_SERIALIZATION =
    Pubkey.parseBase58String("RENtePQcDLrAbxAsP3k8dwVcnNYQ466hi2uKvALjnXx") catch unreachable;

pub const FEATURES = [_]Pubkey{
    DEPRECATE_REWARDS_SYSVAR,
    PICO_INFLATION,
    FULL_INFLATION_DEVNET_AND_TESTNET,
    FULL_INFLATION_MAINNET_VOTE,
    FULL_INFLATION_MAINNET_ENABLE,
    SECP256K1_PROGRAM_ENABLED,
    SPL_TOKEN_V2_MULTISIG_FIX,
    NO_OVERFLOW_RENT_DISTRIBUTION,
    FILTER_STAKE_DELEGATION_ACCOUNTS,
    REQUIRE_CUSTODIAN_FOR_LOCKED_STAKE_AUTHORIZE,
    SPL_TOKEN_V2_SELF_TRANSFER_FIX,
    WARP_TIMESTAMP_AGAIN,
    CHECK_INIT_VOTE_DATA,
    SECP256K1_RECOVER_SYSCALL_ENABLED,
    SYSTEM_TRANSFER_ZERO_CHECK,
    BLAKE3_SYSCALL_ENABLED,
    DEDUPE_CONFIG_PROGRAM_SIGNERS,
    VERIFY_TX_SIGNATURES_LEN,
    VOTE_STAKE_CHECKED_INSTRUCTIONS,
    RENT_FOR_SYSVARS,
    LIBSECP256K1_0_5_UPGRADE_ENABLED,
    TX_WIDE_COMPUTE_CAP,
    SPL_TOKEN_V2_SET_AUTHORITY_FIX,
    MERGE_NONCE_ERROR_INTO_SYSTEM_ERROR,
    DISABLE_FEES_SYSVAR,
    STAKE_MERGE_WITH_UNMATCHED_CREDITS_OBSERVED,
    ZK_TOKEN_SDK_ENABLED,
    CURVE25519_SYSCALL_ENABLED,
    CURVE25519_RESTRICT_MSM_LENGTH,
    VERSIONED_TX_MESSAGE_ENABLED,
    LIBSECP256K1_FAIL_ON_BAD_COUNT,
    LIBSECP256K1_FAIL_ON_BAD_COUNT2,
    INSTRUCTIONS_SYSVAR_OWNED_BY_SYSVAR,
    STAKE_PROGRAM_ADVANCE_ACTIVATING_CREDITS_OBSERVED,
    CREDITS_AUTO_REWIND,
    DEMOTE_PROGRAM_WRITE_LOCKS,
    ED25519_PROGRAM_ENABLED,
    RETURN_DATA_SYSCALL_ENABLED,
    REDUCE_REQUIRED_DEPLOY_BALANCE,
    SOL_LOG_DATA_SYSCALL_ENABLED,
    STAKES_REMOVE_DELEGATION_IF_INACTIVE,
    DO_SUPPORT_REALLOC,
    PREVENT_CALLING_PRECOMPILES_AS_PROGRAMS,
    OPTIMIZE_EPOCH_BOUNDARY_UPDATES,
    REMOVE_NATIVE_LOADER,
    SEND_TO_TPU_VOTE_PORT,
    REQUESTABLE_HEAP_SIZE,
    DISABLE_FEE_CALCULATOR,
    ADD_COMPUTE_BUDGET_PROGRAM,
    NONCE_MUST_BE_WRITABLE,
    SPL_TOKEN_V3_3_0_RELEASE,
    LEAVE_NONCE_ON_SUCCESS,
    REJECT_EMPTY_INSTRUCTION_WITHOUT_PROGRAM,
    FIXED_MEMCPY_NONOVERLAPPING_CHECK,
    REJECT_NON_RENT_EXEMPT_VOTE_WITHDRAWS,
    EVICT_INVALID_STAKES_CACHE_ENTRIES,
    ALLOW_VOTES_TO_DIRECTLY_UPDATE_VOTE_STATE,
    MAX_TX_ACCOUNT_LOCKS,
    REQUIRE_RENT_EXEMPT_ACCOUNTS,
    FILTER_VOTES_OUTSIDE_SLOT_HASHES,
    UPDATE_SYSCALL_BASE_COSTS,
    STAKE_DEACTIVATE_DELINQUENT_INSTRUCTION,
    VOTE_WITHDRAW_AUTHORITY_MAY_CHANGE_AUTHORIZED_VOTER,
    SPL_ASSOCIATED_TOKEN_ACCOUNT_V1_0_4,
    REJECT_VOTE_ACCOUNT_CLOSE_UNLESS_ZERO_CREDIT_EPOCH,
    ADD_GET_PROCESSED_SIBLING_INSTRUCTION_SYSCALL,
    BANK_TRANSACTION_COUNT_FIX,
    DISABLE_BPF_DEPRECATED_LOAD_INSTRUCTIONS,
    DISABLE_BPF_UNRESOLVED_SYMBOLS_AT_RUNTIME,
    RECORD_INSTRUCTION_IN_TRANSACTION_CONTEXT_PUSH,
    SYSCALL_SATURATED_MATH,
    CHECK_PHYSICAL_OVERLAPPING,
    LIMIT_SECP256K1_RECOVERY_ID,
    DISABLE_DEPRECATED_LOADER,
    CHECK_SLICE_TRANSLATION_SIZE,
    STAKE_SPLIT_USES_RENT_SYSVAR,
    ADD_GET_MINIMUM_DELEGATION_INSTRUCTION_TO_STAKE_PROGRAM,
    ERROR_ON_SYSCALL_BPF_FUNCTION_HASH_COLLISIONS,
    REJECT_CALLX_R10,
    DROP_REDUNDANT_TURBINE_PATH,
    EXECUTABLES_INCUR_CPI_DATA_COST,
    FIX_RECENT_BLOCKHASHES,
    UPDATE_REWARDS_FROM_CACHED_ACCOUNTS,
    ENABLE_PARTITIONED_EPOCH_REWARD,
    PARTITIONED_EPOCH_REWARDS_SUPERFEATURE,
    SPL_TOKEN_V3_4_0,
    SPL_ASSOCIATED_TOKEN_ACCOUNT_V1_1_0,
    DEFAULT_UNITS_PER_INSTRUCTION,
    STAKE_ALLOW_ZERO_UNDELEGATED_AMOUNT,
    REQUIRE_STATIC_PROGRAM_IDS_IN_TRANSACTION,
    STAKE_RAISE_MINIMUM_DELEGATION_TO_1_SOL,
    STAKE_MINIMUM_DELEGATION_FOR_REWARDS,
    ADD_SET_COMPUTE_UNIT_PRICE_IX,
    DISABLE_DEPLOY_OF_ALLOC_FREE_SYSCALL,
    INCLUDE_ACCOUNT_INDEX_IN_RENT_ERROR,
    ADD_SHRED_TYPE_TO_SHRED_SEED,
    WARP_TIMESTAMP_WITH_A_VENGEANCE,
    SEPARATE_NONCE_FROM_BLOCKHASH,
    ENABLE_DURABLE_NONCE,
    VOTE_STATE_UPDATE_CREDIT_PER_DEQUEUE,
    QUICK_BAIL_ON_PANIC,
    NONCE_MUST_BE_AUTHORIZED,
    NONCE_MUST_BE_ADVANCEABLE,
    VOTE_AUTHORIZE_WITH_SEED,
    PRESERVE_RENT_EPOCH_FOR_RENT_EXEMPT_ACCOUNTS,
    ENABLE_BPF_LOADER_EXTEND_PROGRAM_IX,
    ENABLE_EARLY_VERIFICATION_OF_ACCOUNT_MODIFICATIONS,
    SKIP_RENT_REWRITES,
    PREVENT_CREDITING_ACCOUNTS_THAT_END_RENT_PAYING,
    CAP_BPF_PROGRAM_INSTRUCTION_ACCOUNTS,
    LOOSEN_CPI_SIZE_RESTRICTION,
    USE_DEFAULT_UNITS_IN_FEE_CALCULATION,
    COMPACT_VOTE_STATE_UPDATES,
    INCREMENTAL_SNAPSHOT_ONLY_INCREMENTAL_HASH_CALCULATION,
    DISABLE_CPI_SETTING_EXECUTABLE_AND_RENT_EPOCH,
    ON_LOAD_PRESERVE_RENT_EPOCH_FOR_RENT_EXEMPT_ACCOUNTS,
    ACCOUNT_HASH_IGNORE_SLOT,
    SET_EXEMPT_RENT_EPOCH_MAX,
    RELAX_AUTHORITY_SIGNER_CHECK_FOR_LOOKUP_TABLE_CREATION,
    STOP_SIBLING_INSTRUCTION_SEARCH_AT_PARENT,
    VOTE_STATE_UPDATE_ROOT_FIX,
    CAP_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION,
    EPOCH_ACCOUNTS_HASH,
    REMOVE_DEPRECATED_REQUEST_UNIT_IX,
    DISABLE_REHASH_FOR_RENT_EPOCH,
    INCREASE_TX_ACCOUNT_LOCK_LIMIT,
    LIMIT_MAX_INSTRUCTION_TRACE_LENGTH,
    CHECK_SYSCALL_OUTPUTS_DO_NOT_OVERLAP,
    ENABLE_BPF_LOADER_SET_AUTHORITY_CHECKED_IX,
    ENABLE_ALT_BN128_SYSCALL,
    SIMPLIFY_ALT_BN128_SYSCALL_ERROR_CODES,
    ENABLE_ALT_BN128_COMPRESSION_SYSCALL,
    FIX_ALT_BN128_MULTIPLICATION_INPUT_LENGTH,
    ENABLE_PROGRAM_REDEPLOYMENT_COOLDOWN,
    COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
    ENABLE_TURBINE_FANOUT_EXPERIMENTS,
    DISABLE_TURBINE_FANOUT_EXPERIMENTS,
    MOVE_SERIALIZED_LEN_PTR_IN_CPI,
    UPDATE_HASHES_PER_TICK,
    ENABLE_BIG_MOD_EXP_SYSCALL,
    DISABLE_BUILTIN_LOADER_OWNERSHIP_CHAINS,
    CAP_TRANSACTION_ACCOUNTS_DATA_SIZE,
    REMOVE_CONGESTION_MULTIPLIER_FROM_FEE_CALCULATION,
    ENABLE_REQUEST_HEAP_FRAME_IX,
    PREVENT_RENT_PAYING_RENT_RECIPIENTS,
    DELAY_VISIBILITY_OF_PROGRAM_DEPLOYMENT,
    APPLY_COST_TRACKER_DURING_REPLAY,
    BPF_ACCOUNT_DATA_DIRECT_MAPPING,
    ADD_SET_TX_LOADED_ACCOUNTS_DATA_SIZE_INSTRUCTION,
    SWITCH_TO_NEW_ELF_PARSER,
    ROUND_UP_HEAP_SIZE,
    REMOVE_BPF_LOADER_INCORRECT_PROGRAM_ID,
    INCLUDE_LOADED_ACCOUNTS_DATA_SIZE_IN_FEE_CALCULATION,
    NATIVE_PROGRAMS_CONSUME_CU,
    SIMPLIFY_WRITABLE_PROGRAM_ACCOUNT_CHECK,
    STOP_TRUNCATING_STRINGS_IN_SYSCALLS,
    CLEAN_UP_DELEGATION_ERRORS,
    VOTE_STATE_ADD_VOTE_LATENCY,
    CHECKED_ARITHMETIC_IN_FEE_VALIDATION,
    LAST_RESTART_SLOT_SYSVAR,
    REDUCE_STAKE_WARMUP_COOLDOWN,
    REVISE_TURBINE_EPOCH_STAKES,
    ENABLE_POSEIDON_SYSCALL,
    TIMELY_VOTE_CREDITS,
    REMAINING_COMPUTE_UNITS_SYSCALL_ENABLED,
    ENABLE_LOADER_V4,
    REQUIRE_RENT_EXEMPT_SPLIT_DESTINATION,
    BETTER_ERROR_CODES_FOR_TX_LAMPORT_CHECK,
    UPDATE_HASHES_PER_TICK2,
    UPDATE_HASHES_PER_TICK3,
    UPDATE_HASHES_PER_TICK4,
    UPDATE_HASHES_PER_TICK5,
    UPDATE_HASHES_PER_TICK6,
    VALIDATE_FEE_COLLECTOR_ACCOUNT,
    DISABLE_RENT_FEES_COLLECTION,
    ENABLE_ZK_TRANSFER_WITH_FEE,
    DROP_LEGACY_SHREDS,
    ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
    ADD_NEW_RESERVED_ACCOUNT_KEYS,
    CONSUME_BLOCKSTORE_DUPLICATE_PROOFS,
    INDEX_ERASURE_CONFLICT_DUPLICATE_PROOFS,
    MERKLE_CONFLICT_DUPLICATE_PROOFS,
    DISABLE_BPF_LOADER_INSTRUCTIONS,
    ENABLE_ZK_PROOF_FROM_ACCOUNT,
    COST_MODEL_REQUESTED_WRITE_LOCK_COST,
    ENABLE_GOSSIP_DUPLICATE_PROOF_INGESTION,
    CHAINED_MERKLE_CONFLICT_DUPLICATE_PROOFS,
    ENABLE_CHAINED_MERKLE_SHREDS,
    REMOVE_ROUNDING_IN_FEE_CALCULATION,
    ENABLE_TOWER_SYNC_IX,
    DEPRECATE_UNUSED_LEGACY_VOTE_PLUMBING,
    REWARD_FULL_PRIORITY_FEE,
    GET_SYSVAR_SYSCALL_ENABLED,
    ABORT_ON_INVALID_CURVE,
    MIGRATE_FEATURE_GATE_PROGRAM_TO_CORE_BPF,
    VOTE_ONLY_FULL_FEC_SETS,
    MIGRATE_CONFIG_PROGRAM_TO_CORE_BPF,
    ENABLE_GET_EPOCH_STAKE_SYSCALL,
    MIGRATE_ADDRESS_LOOKUP_TABLE_PROGRAM_TO_CORE_BPF,
    ZK_ELGAMAL_PROOF_PROGRAM_ENABLED,
    VERIFY_RETRANSMITTER_SIGNATURE,
    MOVE_STAKE_AND_MOVE_LAMPORTS_IXS,
    ED25519_PRECOMPILE_VERIFY_STRICT,
    VOTE_ONLY_RETRANSMITTER_SIGNED_FEC_SETS,
    MOVE_PRECOMPILE_VERIFICATION_TO_SVM,
    ENABLE_TRANSACTION_LOADING_FAILURE_FEES,
    ENABLE_TURBINE_EXTENDED_FANOUT_EXPERIMENTS,
    DEPRECATE_LEGACY_VOTE_IXS,
    DISABLE_SBPF_V0_EXECUTION,
    REENABLE_SBPF_V0_EXECUTION,
    ENABLE_SBPF_V1_DEPLOYMENT_AND_EXECUTION,
    ENABLE_SBPF_V2_DEPLOYMENT_AND_EXECUTION,
    ENABLE_SBPF_V3_DEPLOYMENT_AND_EXECUTION,
    REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS,
    LIFT_CPI_CALLER_RESTRICTION,
    DISABLE_ACCOUNT_LOADER_SPECIAL_CASE,
    ENABLE_SECP256R1_PRECOMPILE,
    ACCOUNTS_LT_HASH,
    SNAPSHOTS_LT_HASH,
    REMOVE_ACCOUNTS_DELTA_HASH,
    MIGRATE_STAKE_PROGRAM_TO_CORE_BPF,
    DEPLETE_CU_METER_ON_VM_FAILURE,
    RESERVE_MINIMAL_CUS_FOR_BUILTIN_INSTRUCTIONS,
    RAISE_BLOCK_LIMITS_TO_50M,
    DROP_UNCHAINED_MERKLE_SHREDS,
    RELAX_INTRABATCH_ACCOUNT_LOCKS,
    CREATE_SLASHING_PROGRAM,
    DISABLE_PARTITIONED_RENT_COLLECTION,
    ENABLE_VOTE_ADDRESS_LEADER_SCHEDULE,
    REQUIRE_STATIC_NONCE_ACCOUNT,
    RAISE_BLOCK_LIMITS_TO_60M,
    MASK_OUT_RENT_EPOCH_IN_VM_SERIALIZATION,
};
