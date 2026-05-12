pub const accounts_db = @import("accountsdb/lib.zig");
pub const bincode = struct {
    const inner = shared.bincode;

    pub const arraylist = inner.arraylist;
    pub const hashmap = inner.hashmap;
    pub const bounded_array = inner.bounded_array;
    pub const int = inner.int;
    pub const list = inner.list;
    pub const optional = inner.optional;
    pub const shortvec = inner.shortvec;

    pub const LimitAllocator = inner.LimitAllocator;
    pub const Params = inner.Params;

    pub const sizeOf = inner.sizeOf;
    pub const readFromSlice = inner.readFromSlice;
    pub const readFromSliceWithLimit = inner.readFromSliceWithLimit;
    pub const writeToSlice = inner.writeToSlice;
    pub const writeAlloc = inner.writeAlloc;
    pub const read = inner.read;
    pub const readWithLimit = inner.readWithLimit;
    pub const readWithConfig = inner.readWithConfig;
    pub const readWithConfigAndLimit = inner.readWithConfigAndLimit;
    pub const readInt = inner.readInt;
    pub const readIntAsLength = inner.readIntAsLength;
    pub const utf8StringCodec = inner.utf8StringCodec;
    pub const readFieldWithConfig = inner.readFieldWithConfig;
    pub const write = inner.write;
    pub const writeWithConfig = inner.writeWithConfig;
    pub const writeFieldWithConfig = inner.writeFieldWithConfig;
    pub const free = inner.free;
    pub const freeWithConfig = inner.freeWithConfig;
    pub const VarIntConfig = inner.VarIntConfig;
    pub const FieldConfig = inner.FieldConfig;
    pub const getConfig = inner.getConfig;
    pub const getFieldConfig = inner.getFieldConfig;
    pub const getSerializedSizeWithSlice = inner.getSerializedSizeWithSlice;
    pub const writeToArray = inner.writeToArray;
    pub const testRoundTrip = inner.testRoundTrip;

    pub const benchmarks = @import("bincode/benchmarks.zig");
};
pub const bloom = shared.bloom;
pub const shared = @import("shared");
pub const config = @import("config.zig");
pub const core = @import("core/lib.zig");
pub const consensus = @import("consensus/lib.zig");
pub const crypto = struct {
    const inner = shared.crypto;

    pub const FnvHasher = inner.FnvHasher;
    pub const bn254 = inner.bn254;
    pub const bls12_381 = inner.bls12_381;
    pub const ed25519 = inner.ed25519;
    pub const EcdsaSignature = inner.EcdsaSignature;

    pub const benchmark = @import("crypto/benchmark.zig");
};
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
pub const vm = shared.vm;
pub const sync = @import("sync/lib.zig");
pub const time = @import("time/lib.zig");
pub const trace = @import("trace/lib.zig");
pub const TransactionSenderService = @import("transaction_sender/Service.zig");
pub const MockTransferService = @import("transaction_sender/MockTransferService.zig");
pub const testing = @import("testing.zig");
pub const utils = struct {
    pub const ahash = @import("utils/ahash.zig");
    pub const allocators = @import("utils/allocators.zig");
    pub const base64 = @import("utils/base64.zig");
    pub const bitflags = @import("utils/bitflags.zig");
    pub const collections = shared.utils.collections;
    pub const deduper = @import("utils/deduper.zig");
    pub const fmt = @import("utils/fmt.zig");
    pub const interface = @import("utils/interface.zig");
    pub const io = @import("utils/io.zig");
    pub const lru = @import("utils/lru.zig");
    pub const merkle_tree = @import("utils/merkle_tree.zig");
    pub const pht = shared.utils.pht;
    pub const service_manager = @import("utils/service.zig");
    pub const tar = @import("utils/tar.zig");
    pub const thread = @import("utils/thread.zig");
    pub const types = shared.utils.types;
};
pub const version = @import("version/version.zig");
pub const zksdk = struct {
    const inner = shared.zksdk;

    pub const elgamal = inner.elgamal;
    pub const pedersen = inner.pedersen;
    pub const merlin = inner.merlin;

    pub const ElGamalCiphertext = inner.ElGamalCiphertext;
    pub const ElGamalKeypair = inner.ElGamalKeypair;
    pub const ElGamalPubkey = inner.ElGamalPubkey;
    pub const GroupedElGamalCiphertext = inner.GroupedElGamalCiphertext;
    pub const Strobe128 = inner.Strobe128;
    pub const Transcript = inner.Transcript;

    pub const CiphertextCiphertextData = inner.CiphertextCiphertextData;
    pub const CiphertextCommitmentData = inner.CiphertextCommitmentData;
    pub const PercentageWithCapData = inner.PercentageWithCapData;
    pub const PubkeyProofData = inner.PubkeyProofData;
    pub const ZeroCiphertextData = inner.ZeroCiphertextData;
    pub const GroupedCiphertext2HandlesData = inner.GroupedCiphertext2HandlesData;
    pub const BatchedGroupedCiphertext2HandlesData = inner.BatchedGroupedCiphertext2HandlesData;
    pub const GroupedCiphertext3HandlesData = inner.GroupedCiphertext3HandlesData;
    pub const BatchedGroupedCiphertext3HandlesData = inner.BatchedGroupedCiphertext3HandlesData;
    pub const bulletproofs = inner.bulletproofs;
    pub const RangeProofU64Data = inner.RangeProofU64Data;
    pub const RangeProofU128Data = inner.RangeProofU128Data;
    pub const RangeProofU256Data = inner.RangeProofU256Data;

    pub const benchmarks = @import("zksdk/benchmarks.zig");
};
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
