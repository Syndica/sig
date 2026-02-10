pub const accounts_db = @import("accountsdb/lib.zig");
pub const bincode = @import("bincode/bincode.zig");
pub const bloom = @import("bloom/lib.zig");
pub const core = @import("core/lib.zig");
pub const consensus = @import("consensus/lib.zig");
pub const debug = @import("debug.zig");
pub const crypto = @import("crypto/lib.zig");
pub const geyser = @import("geyser/lib.zig");
pub const gossip = @import("gossip/lib.zig");
pub const identity = @import("identity.zig");
pub const ledger = @import("ledger/lib.zig");
pub const net = @import("net/lib.zig");
pub const prometheus = @import("prometheus/lib.zig");
pub const rand = @import("rand/rand.zig");
pub const replay = @import("replay/lib.zig");
pub const rpc = @import("rpc/lib.zig");
pub const runtime = @import("runtime/lib.zig");
pub const shred_network = @import("shred_network/lib.zig");
pub const vm = @import("vm/lib.zig");
pub const sync = @import("sync/lib.zig");
pub const time = @import("time/lib.zig");
pub const trace = @import("trace/lib.zig");
pub const transaction_sender = @import("transaction_sender/lib.zig");
pub const testing = @import("testing.zig");
pub const utils = @import("utils/lib.zig");
pub const version = @import("version/version.zig");
pub const zksdk = @import("zksdk/lib.zig");
pub const build_options = @import("build-options");

pub const VALIDATOR_DIR = "validator/";
/// subdirectory of {VALIDATOR_DIR} which contains the accounts database
pub const ACCOUNTS_DB_SUBDIR = "accounts_db/";
/// persistent data used as test inputs
pub const TEST_DATA_DIR = "data/test-data/";
/// ephemeral state produced by tests
pub const TEST_STATE_DIR = "data/test-state/";
pub const FUZZ_DATA_DIR = "data/fuzz-data/";
pub const BENCHMARK_RESULTS_DIR = "results/";
pub const GENESIS_DIR = "data/genesis-files/";
pub const ELF_DATA_DIR = "data/test-elfs/";

/// The maximum cluster size supported by sig. Raise this number to support
/// larger clusters. It's used in cases when we need to assume an upper bound,
/// for example to limit loop iterations to guarantee liveness of certain
/// validator subsystems.
pub const MAX_VALIDATORS = 20_000;

comptime {
    // sig's global assertions/assumptions

    const target = @import("builtin").target;
    if (target.ptrBitWidth() != 64) {
        @compileError("sig only supports 64-bit targets");
    }
}
