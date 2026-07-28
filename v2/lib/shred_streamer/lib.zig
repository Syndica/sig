//! Shred stream library — shared components for streaming shreds from an
//! Agave ledger. Used by both the in-topology service (shred_streamer) and
//! the standalone CLI tool (shred_stream script).

pub const config = @import("config.zig");
pub const agave_blockstore = @import("agave_blockstore.zig");
pub const plan = @import("plan.zig");
pub const stream = @import("stream.zig");

// Convenience re-exports
pub const AgaveBlockstore = agave_blockstore.AgaveBlockstore;
pub const Config = config.Config;
pub const TestMode = config.TestMode;
pub const ProducerStats = config.ProducerStats;
pub const SelectedShredPlan = config.SelectedShredPlan;

pub const produceLedgerPackets = stream.produceLedgerPackets;
pub const buildSelectedShredPlan = plan.buildSelectedShredPlan;
pub const parseArgs = config.parseArgs;
pub const printHelp = config.printHelp;
pub const resolveRocksDbPath = config.resolveRocksDbPath;
