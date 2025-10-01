const std = @import("std");
const sig = @import("sig.zig");
const cli = @import("cli");

const accountsdb_fuzz = sig.accounts_db.fuzz;
const gossip_service_fuzz = sig.gossip.fuzz_service;
const gossip_table_fuzz = sig.gossip.fuzz_table;
const snapshot_fuzz = sig.accounts_db.snapshot.fuzz;
const ledger_fuzz = sig.ledger.fuzz_ledger;
const allocators_fuzz = sig.utils.allocators.fuzzer;

// Supported fuzz filters.
// NOTE: changing these enum variants will require a change to the fuzz/kcov in `scripts/`
pub const FuzzFilter = enum {
    accountsdb,
    snapshot,
    gossip_service,
    gossip_table,
    ledger,
    allocators,
};

const Cmd = struct {
    data_dir: ?[]const u8,
    seed: ?u64,
    fuzzer: ?union(FuzzFilter) {
        accountsdb: accountsdb_fuzz.RunCmd,
        snapshot: snapshot_fuzz.RunCmd,
        gossip_service: gossip_service_fuzz.RunCmd,
        gossip_table: gossip_table_fuzz.RunCmd,
        ledger: ledger_fuzz.RunCmd,
        allocators: allocators_fuzz.RunCmd,
    },

    const parser = cli.Parser(Cmd, .{
        .help = .{
            .short = "Fuzz a component of the validator.",
            .long = null,
        },
        .sub = .{
            .data_dir = .{
                .kind = .named,
                .name_override = null,
                .alias = .d,
                .default_value = null,
                .config = .string,
                .help = "Directory for all fuzzers to store their on-disk data relative to.",
            },
            .seed = .{
                .kind = .named,
                .name_override = null,
                .alias = .s,
                .default_value = null,
                .config = {},
                .help = "Seed for the PRNG for all random actions taken during fuzzing.",
            },
            .fuzzer = .{
                .accountsdb = accountsdb_fuzz.RunCmd.cmd_info,
                .snapshot = snapshot_fuzz.RunCmd.cmd_info,
                .gossip_service = gossip_service_fuzz.RunCmd.cmd_info,
                .gossip_table = gossip_table_fuzz.RunCmd.cmd_info,
                .ledger = ledger_fuzz.RunCmd.cmd_info,
                .allocators = allocators_fuzz.RunCmd.cmd_info,
            },
        },
    });
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);
    const args = argv[1..];

    const stderr = std.io.getStdErr();
    const stderr_tty = std.io.tty.detectConfig(stderr);
    const cmd: Cmd = cmd: {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        break :cmd try Cmd.parser.parse(
            gpa,
            "fuzz",
            stderr_tty,
            stderr.writer(),
            args,
        ) orelse return;
    };
    defer Cmd.parser.free(gpa, cmd);

    const std_logger: *sig.trace.ChannelPrintLogger = try .init(.{
        .allocator = gpa,
        .max_level = .debug,
        .max_buffer = 1 << 20,
    }, null);
    defer std_logger.deinit();
    const logger = std_logger.logger("fuzz");

    const data_dir_name = cmd.data_dir orelse sig.FUZZ_DATA_DIR;
    const seed = cmd.seed orelse std.crypto.random.int(u64);
    const fuzzer = cmd.fuzzer orelse {
        std.debug.print("Missing filter.\n", .{});
        return;
    };

    var data_dir = try std.fs.cwd().makeOpenPath(data_dir_name, .{});
    defer data_dir.close();

    {
        std.debug.print("using seed: {d}\n", .{seed});
        // where seeds are saved (in case of too many logs)
        const seed_file = try data_dir.createFile("fuzz_seeds.txt", .{ .truncate = false });
        defer seed_file.close();
        try seed_file.seekFromEnd(0);
        const now: u64 = @intCast(std.time.timestamp());
        try seed_file.writer().print(
            "{s}: time: {d}, seed: {d}\n",
            .{ @tagName(fuzzer), now, seed },
        );
    }

    const metrics_port: u16 = 12345;
    logger.info().logf("metrics port: {d}", .{metrics_port});
    // TODO: use the GPA here, the server is just leaking because we're losing the handle
    // to it and never deiniting.
    const metrics_thread: std.Thread = try .spawn(.{}, sig.prometheus.servePrometheus, .{
        std.heap.c_allocator,
        sig.prometheus.globalRegistry(),
        metrics_port,
    });
    metrics_thread.detach();

    var sub_data_dir = try data_dir.makeOpenPath(@tagName(fuzzer), .{});
    defer sub_data_dir.close();

    switch (fuzzer) {
        .accountsdb,
        => |run_cmd| try accountsdb_fuzz.run(
            gpa,
            .from(logger),
            seed,
            sub_data_dir,
            run_cmd,
        ),

        .snapshot,
        => |run_cmd| try snapshot_fuzz.run(gpa, seed, run_cmd),

        .gossip_service,
        => |run_cmd| try gossip_service_fuzz.run(gpa, seed, run_cmd),

        .gossip_table,
        => |run_cmd| try gossip_table_fuzz.run(gpa, .from(logger), seed, run_cmd),

        .allocators,
        => |run_cmd| try allocators_fuzz.run(gpa, seed, run_cmd),

        .ledger,
        => |run_cmd| try ledger_fuzz.run(gpa, .from(logger), seed, sub_data_dir, run_cmd),
    }
}
