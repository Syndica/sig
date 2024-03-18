const std = @import("std");
const cli = @import("zig-cli");
const base58 = @import("base58-zig");
const enumFromName = @import("../utils/types.zig").enumFromName;
const getOrInitIdentity = @import("./helpers.zig").getOrInitIdentity;
const ContactInfo = @import("../gossip/data.zig").ContactInfo;
const SOCKET_TAG_GOSSIP = @import("../gossip/data.zig").SOCKET_TAG_GOSSIP;
const Logger = @import("../trace/log.zig").Logger;
const Level = @import("../trace/level.zig").Level;
const io = std.io;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const SocketAddr = @import("../net/net.zig").SocketAddr;
const echo = @import("../net/echo.zig");
const GossipService = @import("../gossip/service.zig").GossipService;
const servePrometheus = @import("../prometheus/http.zig").servePrometheus;
const globalRegistry = @import("../prometheus/registry.zig").globalRegistry;
const Registry = @import("../prometheus/registry.zig").Registry;
const getWallclockMs = @import("../gossip/data.zig").getWallclockMs;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = gpa.allocator();
const base58Encoder = base58.Encoder.init(.{});

var gossip_port_option = cli.Option{
    .long_name = "gossip-port",
    .help = "The port to run gossip listener - default: 8001",
    .short_alias = 'p',
    .value = cli.OptionValue{ .int = 8001 },
    .required = false,
    .value_name = "Gossip Port",
};

var gossip_entrypoints_option = cli.Option{
    .long_name = "entrypoint",
    .help = "gossip address of the entrypoint validators",
    .short_alias = 'e',
    .value = cli.OptionValue{ .string_list = null },
    .required = false,
    .value_name = "Entrypoints",
};

var gossip_spy_node_option = cli.Option{
    .long_name = "spy-node",
    .help = "run as a gossip spy node (minimize outgoing packets)",
    .value = cli.OptionValue{ .bool = false },
    .required = false,
    .value_name = "Spy Node",
};

var log_level_option = cli.Option{
    .long_name = "log-level",
    .help = "The amount of detail to log (default = debug)",
    .short_alias = 'l',
    .value = cli.OptionValue{ .string = "debug" },
    .required = false,
    .value_name = "err|warn|info|debug",
};

var metrics_port_option = cli.Option{
    .long_name = "metrics-port",
    .help = "port to expose prometheus metrics via http",
    .short_alias = 'm',
    .value = cli.OptionValue{ .int = 12345 },
    .required = false,
    .value_name = "port_number",
};

var app = &cli.App{
    .name = "sig",
    .description = "Sig is a Solana client implementation written in Zig.\nThis is still a WIP, PRs welcome.",
    .version = "0.1.1",
    .author = "Syndica & Contributors",
    .options = &.{ &log_level_option, &metrics_port_option },
    .subcommands = &.{
        &cli.Command{
            .name = "identity",
            .help = "Get own identity",
            .description =
            \\Gets own identity (Pubkey) or creates one if doesn't exist.
            \\
            \\NOTE: Keypair is saved in $HOME/.sig/identity.key.
            ,
            .action = identity,
        },
        &cli.Command{ .name = "gossip", .help = "Run gossip client", .description = 
        \\Start Solana gossip client on specified port.
        , .action = gossip, .options = &.{
            &gossip_port_option,
            &gossip_entrypoints_option,
            &gossip_spy_node_option,
        } },
    },
};

// prints (and creates if DNE) pubkey in ~/.sig/identity.key
fn identity(_: []const []const u8) !void {
    var logger = Logger.init(gpa_allocator, try enumFromName(Level, log_level_option.value.string.?));
    defer logger.deinit();
    logger.spawn();

    const keypair = try getOrInitIdentity(gpa_allocator, logger);
    var pubkey: [50]u8 = undefined;
    var size = try base58Encoder.encode(&keypair.public_key.toBytes(), &pubkey);
    try std.io.getStdErr().writer().print("Identity: {s}\n", .{pubkey[0..size]});
}

// gossip entrypoint
fn gossip(_: []const []const u8) !void {
    // var logger = Logger.init(gpa_allocator, try enumFromName(Level, log_level_option.value.string.?));
    // defer logger.deinit();
    // logger.spawn();

    var logger: Logger = .noop;

    const metrics_thread = try spawnMetrics(gpa_allocator, logger);

    var my_keypair = try getOrInitIdentity(gpa_allocator, logger);

    var gossip_port: u16 = @intCast(gossip_port_option.value.int.?);
    var gossip_address = SocketAddr.initIpv4(.{ 0, 0, 0, 0 }, gossip_port);
    logger.infof("gossip port: {d}", .{gossip_port});

    // setup contact info
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = ContactInfo.init(gpa_allocator, my_pubkey, getWallclockMs(), 0);
    try contact_info.setSocket(SOCKET_TAG_GOSSIP, gossip_address);

    var entrypoints = std.ArrayList(SocketAddr).init(gpa_allocator);
    defer entrypoints.deinit();
    if (gossip_entrypoints_option.value.string_list) |entrypoints_strs| {
        for (entrypoints_strs) |entrypoint| {
            var value = SocketAddr.parse(entrypoint) catch {
                std.debug.print("Invalid entrypoint: {s}\n", .{entrypoint});
                return;
            };
            try entrypoints.append(value);
        }
    }

    // log entrypoints
    var entrypoint_string = try gpa_allocator.alloc(u8, 53 * entrypoints.items.len);
    defer gpa_allocator.free(entrypoint_string);
    var stream = std.io.fixedBufferStream(entrypoint_string);
    var writer = stream.writer();
    for (0.., entrypoints.items) |i, entrypoint| {
        try entrypoint.toAddress().format("", .{}, writer);
        if (i != entrypoints.items.len - 1) try writer.writeAll(", ");
    }
    logger.infof("entrypoints: {s}", .{entrypoint_string[0..stream.pos]});

    // determine our shred version. in the solana-labs client, this approach is only
    // used for validation. normally, shred version comes from the snapshot.
    contact_info.shred_version = loop: for (entrypoints.items) |entrypoint| {
        if (echo.requestIpEcho(gpa_allocator, entrypoint.toAddress(), .{})) |response| {
            if (response.shred_version) |shred_version| {
                var addr_str = entrypoint.toString();
                logger.infof(
                    "shred version: {} - from entrypoint ip echo: {s}",
                    .{ shred_version.value, addr_str[0][0..addr_str[1]] },
                );
                break shred_version.value;
            }
        } else |_| {}
    } else {
        logger.warn("could not get a shred version from an entrypoint");
        break :loop 0;
    };

    var exit = std.atomic.Atomic(bool).init(false);
    var gossip_service = try GossipService.init(
        gpa_allocator,
        contact_info,
        my_keypair,
        entrypoints,
        &exit,
        logger,
    );
    defer gossip_service.deinit();

    const spy_node = gossip_spy_node_option.value.bool;
    var handle = try std.Thread.spawn(
        .{},
        GossipService.run,
        .{ &gossip_service, spy_node },
    );

    const GossipTable = @import("../gossip/table.zig").GossipTable;
    const SOCKET_TAG_RPC = @import("../gossip/data.zig").SOCKET_TAG_RPC;
    const SlotAndHash = @import("../gossip/data.zig").SlotAndHash;

    const GENESIS_FILE: []const u8 = "genesis.tar.bz2";

    const PeerSnapshotHash = struct {
        contact_info: ContactInfo,
        full_snapshot: SlotAndHash,
        inc_snapshot: ?SlotAndHash,
    };
    var has_genesis = false;

    // TMP - TODO: remove later
    var ci_buf: [10]ContactInfo = undefined;
    var valid_buf: [10]u8 = undefined;
    @memset(&valid_buf, 0);

    var peer_snapshots = std.ArrayList(PeerSnapshotHash).init(gpa_allocator);
    defer peer_snapshots.deinit();

    while (true) {
        std.debug.print("sleeping...\n", .{});
        std.time.sleep(std.time.ns_per_s * 3);

        var lg = gossip_service.gossip_table_rw.read();
        defer lg.unlock();
        const table: *const GossipTable = lg.get();

        var cis = table.getContactInfos(&ci_buf, 0);
        var is_me_cis: u8 = 0;
        var invalid_shred: u8 = 0;
        for (cis, 0..) |*ci, index| {
            const is_me = ci.pubkey.equals(&my_pubkey);
            if (is_me) {
                is_me_cis += 1;
                continue;
            }
            const matching_shred_version = contact_info.shred_version == ci.shred_version or contact_info.shred_version == 0;
            if (!matching_shred_version) {
                invalid_shred += 1;
                continue;
            }
            valid_buf[index] = 1;
        }

        var valid_count: usize = 0;
        for (0..valid_buf.len) |i| {
            if (valid_buf[i] == 1) {
                valid_count += 1;

                var ci = &ci_buf[i];
                if (ci.getSocket(SOCKET_TAG_RPC)) |rpc_socket| {
                    const r = rpc_socket.toString();
                    // genesis download
                    const genesis_url = try std.fmt.allocPrint(gpa_allocator, "http://{s}/{s}", .{
                        r[0][0..r[1]],
                        GENESIS_FILE,
                    });
                    // _ = genesis_url;
                    std.debug.print("genesis_url: {s}\n", .{genesis_url});

                    if (!has_genesis) {
                        // TODO: download genesis file
                        // TODO: unpack genesis file (bzip)
                        // has_genesis = true;
                    }

                    // snapshot download
                    const pubkey = ci.pubkey;
                    if (table.get(.{ .SnapshotHashes = pubkey })) |snapshot_hash| {
                        const hashes = snapshot_hash.value.data.SnapshotHashes;

                        var max_inc_hash: ?SlotAndHash = null;
                        for (hashes.incremental) |inc_hash| {
                            if (max_inc_hash == null or inc_hash.slot > max_inc_hash.?.slot) {
                                max_inc_hash = inc_hash;
                            }
                        }
                        try peer_snapshots.append(.{
                            .contact_info = ci.*,
                            .full_snapshot = hashes.full,
                            .inc_snapshot = max_inc_hash,
                        });
                    }
                }
            }
        }

        for (peer_snapshots.items) |peer| {
            const rpc_socket = peer.contact_info.getSocket(SOCKET_TAG_RPC).?;
            const r = rpc_socket.toString();
            const snapshot_url = try std.fmt.allocPrint(gpa_allocator, "http://{s}/snapshot-{d}-{s}.{s}", .{
                r[0][0..r[1]],
                peer.full_snapshot.slot,
                peer.full_snapshot.hash,
                "tar.zst",
            });
            std.debug.print("snapshot_url: {s}\n", .{snapshot_url});

            if (peer.inc_snapshot) |inc_snapshot| {
                const inc_snapshot_url = try std.fmt.allocPrint(gpa_allocator, "http://{s}/incremental-snapshot-{d}-{d}-{s}.{s}", .{
                    r[0][0..r[1]],
                    peer.full_snapshot.slot,
                    inc_snapshot.slot,
                    inc_snapshot.hash,
                    "tar.zst",
                });
                std.debug.print("inc_snapshot_url: {s}\n", .{inc_snapshot_url});
            }

            // TODO: download snapshot file
            // TODO: unpack snapshot file

            std.debug.print("---------\n", .{});
        }

        peer_snapshots.clearRetainingCapacity();
    }

    // only contact infos which have a valid rpc port

    handle.join();
    metrics_thread.detach();
}

/// Initializes the global registry. Returns error if registry was already initialized.
/// Spawns a thread to serve the metrics over http on the CLI configured port.
/// Uses same allocator for both registry and http adapter.
fn spawnMetrics(allocator: std.mem.Allocator, logger: Logger) !std.Thread {
    var metrics_port: u16 = @intCast(metrics_port_option.value.int.?);
    logger.infof("metrics port: {d}", .{metrics_port});
    const registry = globalRegistry();
    return try std.Thread.spawn(.{}, servePrometheus, .{ allocator, registry, metrics_port });
}

pub fn run() !void {
    return cli.run(app, gpa_allocator);
}
