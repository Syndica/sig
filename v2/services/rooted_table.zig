const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");

const tel = lib.telemetry;

const SnapshotConfig = lib.snapshot.SnapshotConfig;
const SnapshotReadyRing = lib.snapshot.SnapshotReadyRing;
const SnapshotIter = lib.solana.snapshot.SnapshotIter;

const Rooted = lib.accounts_db.Rooted;
const RootedConfig = lib.accounts_db.RootedConfig;
const AccountPool = lib.accounts_db.AccountPool;
const AccountLookups = lib.accounts_db.AccountLookups;
const Table = lib.accounts_db.Table;

comptime {
    _ = start;
}

pub const name = .rooted_table;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {
    rooted_config: *const RootedConfig,
};

pub const ReadWrite = struct {
    rooted_lookups: *lib.accounts_db.TableLookups,
    tel: *tel.Region,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    const table_memory_len = ro.rooted_config.memory_len;
    logger.info().logf("rooted_table started with {B:.2}", .{table_memory_len});

    const Global = struct {
        var table: Table = blk: {
            @setRuntimeSafety(false);
            break :blk undefined;
        };
    };

    const seed: u64 = 0; // TODO: randomly generate
    const table = &Global.table;
    table.* = try Table.init(seed, table_memory_len);
    defer table.deinit();

    var put_req = rw.rooted_lookups.put.get(.reader);
    var get_req = rw.rooted_lookups.get.in.get(.reader);
    var get_resp = rw.rooted_lookups.get.out.get(.writer);

    while (true) : (std.atomic.spinLoopHint()) {
        if (put_req.peek() != null) {
            var batch = Table.PutBatch.empty;
            while (put_req.next()) |req| {
                table.put(&batch, &req.pubkey, req.slot, req.value);
                put_req.markUsed();
            }
            table.flushPuts(&batch);
            rw.rooted_lookups.count.store(table.count, .monotonic);
        }

        while (get_req.next()) |req| {
            const result = table.get(req);
            get_req.markUsed();

            const res_ptr = while (true) : (std.atomic.spinLoopHint()) 
                break get_resp.next() orelse continue;
            res_ptr.* = result;
            get_resp.markUsed();
        }
    }
}
