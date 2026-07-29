const std = @import("std");
const sig = @import("sig");

const ExitCondition = sig.sync.ExitCondition;

const Logger = sig.trace.log.Logger("test_mock_transfers");

const DEFAULT_RPC_URL = "https://api.testnet.solana.com";

fn printUsage() void {
    std.debug.print(
        "Usage:\n" ++
            "  test-mock-transfers <num_transactions> [options]\n\n" ++
            "Arguments:\n" ++
            "  <num_transactions>    Number of transactions to send (required)\n\n" ++
            "Options:\n" ++
            "  --rpc-url <url>           RPC URL for state queries (default: {s})\n" ++
            "  --submit-rpc-url <url>    RPC URL for submitting transactions " ++
            "(defaults to --rpc-url)\n" ++
            "  --skip-preflight          Skip preflight simulation\n\n" ++
            "Example:\n" ++
            "  test-mock-transfers 10\n" ++
            "  test-mock-transfers 10 --skip-preflight\n" ++
            "  test-mock-transfers 10 --rpc-url https://api.testnet.solana.com " ++
            "--submit-rpc-url http://localhost:8899\n",
        .{DEFAULT_RPC_URL},
    );
}

pub fn main() !void {
    const logger = Logger{
        .impl = .direct_print,
        .max_level = .debug,
        .filters = .debug,
    };

    var exit_flag = std.atomic.Value(bool).init(false);
    const exit = ExitCondition{ .unordered = &exit_flag };
    errdefer |err| {
        logger.err().logf("exiting with error: {any}\n", .{err});
        exit.setExit();
    }

    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa_state.deinit() == .leak) {
        logger.err().log("Memory leak detected");
    };
    const gpa = gpa_state.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len < 2) {
        printUsage();
        return error.InvalidArgs;
    }

    const transfers = std.fmt.parseUnsigned(u64, args[1], 10) catch {
        std.debug.print("Error: invalid number of transactions '{s}'\n", .{args[1]});
        printUsage();
        return error.InvalidArgs;
    };

    var rpc_url: []const u8 = DEFAULT_RPC_URL;
    var submit_rpc_url: ?[]const u8 = null;
    var skip_preflight: bool = false;

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--rpc-url")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --rpc-url requires a value\n", .{});
                printUsage();
                return error.InvalidArgs;
            }
            rpc_url = args[i];
        } else if (std.mem.eql(u8, args[i], "--submit-rpc-url")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --submit-rpc-url requires a value\n", .{});
                printUsage();
                return error.InvalidArgs;
            }
            submit_rpc_url = args[i];
        } else if (std.mem.eql(u8, args[i], "--skip-preflight")) {
            skip_preflight = true;
        } else {
            std.debug.print("Error: unexpected argument '{s}'\n", .{args[i]});
            printUsage();
            return error.InvalidArgs;
        }
    }

    const effective_submit_url = submit_rpc_url orelse rpc_url;

    if (std.mem.indexOf(u8, rpc_url, "mainnet") != null or
        std.mem.indexOf(u8, effective_submit_url, "mainnet") != null)
    {
        @panic("Refusing to run against mainnet. Use a testnet or devnet RPC URL instead.");
    }

    logger.info().logf("Starting mock transfer test with {d} transactions", .{transfers});
    logger.info().logf("  RPC URL (queries):    {s}", .{rpc_url});
    logger.info().logf("  RPC URL (submit):     {s}", .{effective_submit_url});
    logger.info().logf("  Skip preflight:       {}", .{skip_preflight});

    var mock_transfer_service = sig.MockTransferService{
        .exit = exit,
        .logger = .from(logger),
        .client = try .init(gpa, rpc_url, .{
            .max_retries = 5,
            .logger = .noop,
        }),
        .submit = .{ .rpc = try .init(gpa, effective_submit_url, .{
            .max_retries = 5,
            .logger = .noop,
        }) },
        .skip_preflight = skip_preflight,
        .transfers = transfers,
    };
    defer mock_transfer_service.deinit();

    try mock_transfer_service.run(gpa);

    logger.info().logf("Mock transfer test completed: {d}/{d} successful", .{
        mock_transfer_service.successful,
        transfers,
    });

    exit.setExit();
}
