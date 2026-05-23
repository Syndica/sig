//! Streams raw shreds from an Agave ledger to a UDP target.

const std = @import("std");
const rocks = @import("rocksdb");
const rocks_c = @import("rocksdb-c");

const Allocator = std.mem.Allocator;
const Slot = u64;

const agave_cf_default = "default";
const agave_cf_meta = "meta";
const agave_cf_data_shred = "data_shred";
const agave_cf_code_shred = "code_shred";
const max_shred_packet_bytes: usize = 1232;

const Config = struct {
    ledger: []const u8,
    target: []const u8,
    start_slot: ?Slot = null,
    end_slot: ?Slot = null,
    rate_hz: ?f64 = null,
    dry_run: bool = false,
};

const PartialConfig = struct {
    ledger: ?[]const u8 = null,
    target: ?[]const u8 = null,
    start_slot: ?Slot = null,
    end_slot: ?Slot = null,
    rate_hz: ?f64 = null,
    dry_run: bool = false,

    fn finalize(self: PartialConfig) ParseArgsError!Config {
        const ledger = self.ledger orelse {
            std.debug.print("missing required argument: --ledger <path>\n", .{});
            return error.InvalidArguments;
        };
        const target = self.target orelse {
            std.debug.print("missing required argument: --target <ip:port>\n", .{});
            return error.InvalidArguments;
        };

        if (self.start_slot != null and self.end_slot != null and self.end_slot.? < self.start_slot.?) {
            std.debug.print("--end-slot must be greater than or equal to --start-slot\n", .{});
            return error.InvalidArguments;
        }

        return .{
            .ledger = ledger,
            .target = target,
            .start_slot = self.start_slot,
            .end_slot = self.end_slot,
            .rate_hz = self.rate_hz,
            .dry_run = self.dry_run,
        };
    }
};

const ParseResult = union(enum) {
    config: Config,
    help,
};

const ParseArgsError = error{
    InvalidArguments,
};

const Arg = enum {
    help,
    ledger,
    target,
    start_slot,
    end_slot,
    rate_hz,
    dry_run,

    fn parse(raw: []const u8) ?Arg {
        if (std.mem.eql(u8, raw, "--help") or std.mem.eql(u8, raw, "-h")) return .help;
        if (std.mem.eql(u8, raw, "--ledger")) return .ledger;
        if (std.mem.eql(u8, raw, "--target")) return .target;
        if (std.mem.eql(u8, raw, "--start-slot")) return .start_slot;
        if (std.mem.eql(u8, raw, "--end-slot")) return .end_slot;
        if (std.mem.eql(u8, raw, "--rate-hz")) return .rate_hz;
        if (std.mem.eql(u8, raw, "--dry-run")) return .dry_run;
        return null;
    }

    fn name(arg: Arg) []const u8 {
        return switch (arg) {
            .help => "--help",
            .ledger => "--ledger",
            .target => "--target",
            .start_slot => "--start-slot",
            .end_slot => "--end-slot",
            .rate_hz => "--rate-hz",
            .dry_run => "--dry-run",
        };
    }
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    const parse_result = parseArgs(argv[1..]) catch |err| switch (err) {
        error.InvalidArguments => {
            printHelp();
            return err;
        },
    };

    switch (parse_result) {
        .help => printHelp(),
        .config => |config| try run(gpa, config),
    }
}

fn run(allocator: Allocator, config: Config) !void {
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    var blockstore = try AgaveBlockstore.open(allocator, config.ledger);
    defer blockstore.deinit();

    try stdout.print("shred-stream config:\n", .{});
    try stdout.print("  ledger: {s}\n", .{config.ledger});
    try stdout.print("  rocksdb: {s}\n", .{blockstore.rocksdb_path});
    try stdout.print("  target: {s}\n", .{config.target});
    try stdout.print("  start_slot: {?d}\n", .{config.start_slot});
    try stdout.print("  end_slot: {?d}\n", .{config.end_slot});
    try stdout.print("  rate_hz: {?}\n", .{config.rate_hz});
    try stdout.print("  dry_run: {}\n", .{config.dry_run});
    try stdout.print("  column_families:\n", .{});
    try stdout.print("    {s}: present\n", .{agave_cf_meta});
    try stdout.print("    {s}: present\n", .{agave_cf_data_shred});
    try stdout.print("    {s}: {s}\n", .{ agave_cf_code_shred, if (blockstore.has_code_shred) "present" else "missing" });

    if (!blockstore.has_code_shred) {
        try stdout.print("warning: missing optional {s} column family; streaming data shreds only\n", .{agave_cf_code_shred});
    }

    if (config.dry_run) {
        const stats = try scanLedger(&blockstore, config);
        try printLedgerStats(stdout, stats);
    } else {
        var sink: NoopPacketSink = .{};
        const stats = try walkLedgerPackets(
            &blockstore,
            config,
            NoopPacketSink,
            &sink,
            ignoreProducedPacket,
        );
        try printProducerStats(stdout, stats);
        try stdout.print("sender: not implemented yet\n", .{});
    }

    try stdout.flush();
}

const AgaveBlockstore = struct {
    allocator: Allocator,
    rocksdb_path: []const u8,
    db: rocks.DB,
    column_families: []const rocks.ColumnFamily,
    has_code_shred: bool,

    fn open(allocator: Allocator, ledger_path: []const u8) !AgaveBlockstore {
        const rocksdb_path = try resolveRocksDbPath(allocator, ledger_path);
        errdefer allocator.free(rocksdb_path);

        var available_cfs = try listColumnFamilies(allocator, rocksdb_path);
        defer available_cfs.deinit();

        try requireColumnFamily(&available_cfs, agave_cf_default);
        try requireColumnFamily(&available_cfs, agave_cf_meta);
        try requireColumnFamily(&available_cfs, agave_cf_data_shred);

        const has_code_shred = available_cfs.contains(agave_cf_code_shred);
        const cfs = try columnFamilyDescriptions(allocator, has_code_shred);
        defer allocator.free(cfs);

        const rocksdb_path_z = try allocator.dupeZ(u8, rocksdb_path);
        defer allocator.free(rocksdb_path_z);

        var err_data: ?rocks.Data = null;
        defer if (err_data) |err| err.deinit();

        var db, const opened_cfs = rocks.DB.open(
            allocator,
            rocksdb_path_z,
            .{},
            cfs,
            true,
            &err_data,
        ) catch |err| {
            if (err_data) |rocks_err| {
                std.debug.print("failed to open RocksDB at {s}: {s}\n", .{ rocksdb_path, rocks_err.data });
            }
            return err;
        };
        errdefer db.deinit();
        errdefer freeOpenedColumnFamilies(allocator, opened_cfs);

        return .{
            .allocator = allocator,
            .rocksdb_path = rocksdb_path,
            .db = db,
            .column_families = opened_cfs,
            .has_code_shred = has_code_shred,
        };
    }

    fn deinit(self: *AgaveBlockstore) void {
        freeOpenedColumnFamilies(self.allocator, self.column_families);
        self.db.deinit();
        self.allocator.free(self.rocksdb_path);
    }

    fn columnFamily(self: *const AgaveBlockstore, name: []const u8) !rocks.ColumnFamilyHandle {
        for (self.column_families) |column_family| {
            if (std.mem.eql(u8, column_family.name, name)) return column_family.handle;
        }
        return error.MissingColumnFamily;
    }
};

const LedgerStats = struct {
    slots: SlotStats,
    data_shreds: ShredStats,
    code_shreds: ?ShredStats,
};

const SlotStats = struct {
    total: u64 = 0,
    selected: u64 = 0,
    first: ?Slot = null,
    last: ?Slot = null,
    selected_first: ?Slot = null,
    selected_last: ?Slot = null,

    fn record(self: *SlotStats, slot: Slot, selected: bool) void {
        self.total += 1;
        self.first = minOptional(self.first, slot);
        self.last = maxOptional(self.last, slot);

        if (!selected) return;
        self.selected += 1;
        self.selected_first = minOptional(self.selected_first, slot);
        self.selected_last = maxOptional(self.selected_last, slot);
    }
};

const ShredKey = struct {
    slot: Slot,
    index: u64,
};

const ShredKind = enum {
    data,
    code,

    fn columnFamilyName(kind: ShredKind) []const u8 {
        return switch (kind) {
            .data => agave_cf_data_shred,
            .code => agave_cf_code_shred,
        };
    }
};

const RawShredPacket = struct {
    kind: ShredKind,
    key: ShredKey,
    payload: []const u8,
};

const ProducerStats = struct {
    slots: u64 = 0,
    data_packets: u64 = 0,
    code_packets: u64 = 0,
    payload_bytes: u64 = 0,

    fn recordSlot(self: *ProducerStats) void {
        self.slots += 1;
    }

    fn recordPacket(self: *ProducerStats, packet: RawShredPacket) void {
        switch (packet.kind) {
            .data => self.data_packets += 1,
            .code => self.code_packets += 1,
        }
        self.payload_bytes += @intCast(packet.payload.len);
    }
};

const NoopPacketSink = struct {};

fn ignoreProducedPacket(_: *NoopPacketSink, _: RawShredPacket) !void {}

const ShredStats = struct {
    total_packets: u64 = 0,
    selected_packets: u64 = 0,
    total_payload_bytes: u64 = 0,
    selected_payload_bytes: u64 = 0,
    max_packet_bytes: usize = 0,
    selected_max_packet_bytes: usize = 0,
    oversized_packets: u64 = 0,
    selected_oversized_packets: u64 = 0,
    first_slot: ?Slot = null,
    last_slot: ?Slot = null,
    selected_first_slot: ?Slot = null,
    selected_last_slot: ?Slot = null,

    fn record(self: *ShredStats, key: ShredKey, packet_len: usize, selected: bool) void {
        self.total_packets += 1;
        self.total_payload_bytes += @intCast(packet_len);
        self.max_packet_bytes = @max(self.max_packet_bytes, packet_len);
        if (packet_len > max_shred_packet_bytes) self.oversized_packets += 1;
        self.first_slot = minOptional(self.first_slot, key.slot);
        self.last_slot = maxOptional(self.last_slot, key.slot);

        if (!selected) return;
        self.selected_packets += 1;
        self.selected_payload_bytes += @intCast(packet_len);
        self.selected_max_packet_bytes = @max(self.selected_max_packet_bytes, packet_len);
        if (packet_len > max_shred_packet_bytes) self.selected_oversized_packets += 1;
        self.selected_first_slot = minOptional(self.selected_first_slot, key.slot);
        self.selected_last_slot = maxOptional(self.selected_last_slot, key.slot);
    }
};

fn scanLedger(blockstore: *const AgaveBlockstore, config: Config) !LedgerStats {
    return .{
        .slots = try scanSlots(blockstore, config),
        .data_shreds = try scanShreds(blockstore, config, agave_cf_data_shred),
        .code_shreds = if (blockstore.has_code_shred)
            try scanShreds(blockstore, config, agave_cf_code_shred)
        else
            null,
    };
}

fn walkLedgerPackets(
    blockstore: *const AgaveBlockstore,
    config: Config,
    comptime Context: type,
    context: *Context,
    comptime handlePacket: fn (*Context, RawShredPacket) anyerror!void,
) !ProducerStats {
    var stats: ProducerStats = .{};

    var start_key_buf: [8]u8 = undefined;
    const start_key: ?[]const u8 = if (config.start_slot) |slot| start_key: {
        writeSlotKey(&start_key_buf, slot);
        break :start_key start_key_buf[0..];
    } else null;

    var slot_iter = blockstore.db.iterator(try blockstore.columnFamily(agave_cf_meta), .forward, start_key);
    defer slot_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try slot_iter.next(&err_data)) |entry| {
        const slot = parseSlotKey(entry[0].data) catch |err| {
            std.debug.print("invalid {s} key length: {d}\n", .{ agave_cf_meta, entry[0].data.len });
            return err;
        };
        if (pastEndSlot(config, slot)) break;
        if (!slotSelected(config, slot)) continue;

        stats.recordSlot();
        try walkSlotShreds(blockstore, slot, .data, Context, context, handlePacket, &stats);
        if (blockstore.has_code_shred) {
            try walkSlotShreds(blockstore, slot, .code, Context, context, handlePacket, &stats);
        }
    }

    return stats;
}

fn walkSlotShreds(
    blockstore: *const AgaveBlockstore,
    slot: Slot,
    kind: ShredKind,
    comptime Context: type,
    context: *Context,
    comptime handlePacket: fn (*Context, RawShredPacket) anyerror!void,
    stats: *ProducerStats,
) !void {
    var start_key_buf: [16]u8 = undefined;
    writeShredKey(&start_key_buf, .{ .slot = slot, .index = 0 });

    var iter = blockstore.db.iterator(
        try blockstore.columnFamily(kind.columnFamilyName()),
        .forward,
        start_key_buf[0..],
    );
    defer iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try iter.next(&err_data)) |entry| {
        const key = parseShredKey(entry[0].data) catch |err| {
            std.debug.print("invalid {s} key length: {d}\n", .{ kind.columnFamilyName(), entry[0].data.len });
            return err;
        };
        if (key.slot != slot) break;
        if (entry[1].data.len > max_shred_packet_bytes) return error.ShredPacketTooLarge;

        const packet: RawShredPacket = .{
            .kind = kind,
            .key = key,
            .payload = entry[1].data,
        };
        try handlePacket(context, packet);
        stats.recordPacket(packet);
    }
}

fn scanSlots(blockstore: *const AgaveBlockstore, config: Config) !SlotStats {
    var stats: SlotStats = .{};

    var start_key_buf: [8]u8 = undefined;
    const start_key: ?[]const u8 = if (config.start_slot) |slot| start_key: {
        writeSlotKey(&start_key_buf, slot);
        break :start_key start_key_buf[0..];
    } else null;

    var iter = blockstore.db.iterator(try blockstore.columnFamily(agave_cf_meta), .forward, start_key);
    defer iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try iter.next(&err_data)) |entry| {
        const slot = parseSlotKey(entry[0].data) catch |err| {
            std.debug.print("invalid {s} key length: {d}\n", .{ agave_cf_meta, entry[0].data.len });
            return err;
        };
        if (pastEndSlot(config, slot)) break;
        stats.record(slot, slotSelected(config, slot));
    }

    return stats;
}

fn scanShreds(blockstore: *const AgaveBlockstore, config: Config, column_family_name: []const u8) !ShredStats {
    var stats: ShredStats = .{};

    var start_key_buf: [16]u8 = undefined;
    const start_key: ?[]const u8 = if (config.start_slot) |slot| start_key: {
        writeShredKey(&start_key_buf, .{ .slot = slot, .index = 0 });
        break :start_key start_key_buf[0..];
    } else null;

    var iter = blockstore.db.iterator(try blockstore.columnFamily(column_family_name), .forward, start_key);
    defer iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try iter.next(&err_data)) |entry| {
        const key = parseShredKey(entry[0].data) catch |err| {
            std.debug.print("invalid {s} key length: {d}\n", .{ column_family_name, entry[0].data.len });
            return err;
        };
        if (pastEndSlot(config, key.slot)) break;
        stats.record(key, entry[1].data.len, slotSelected(config, key.slot));
    }

    return stats;
}

fn printLedgerStats(stdout: *std.Io.Writer, stats: LedgerStats) !void {
    try stdout.print("ledger_stats:\n", .{});
    try stdout.print("  max_packet_bytes: {d}\n", .{max_shred_packet_bytes});

    try stdout.print("  slots:\n", .{});
    try stdout.print("    total: {d}\n", .{stats.slots.total});
    try stdout.print("    first: {?d}\n", .{stats.slots.first});
    try stdout.print("    last: {?d}\n", .{stats.slots.last});
    try stdout.print("    selected: {d}\n", .{stats.slots.selected});
    try stdout.print("    selected_first: {?d}\n", .{stats.slots.selected_first});
    try stdout.print("    selected_last: {?d}\n", .{stats.slots.selected_last});

    try printShredStats(stdout, agave_cf_data_shred, stats.data_shreds);
    if (stats.code_shreds) |code_shreds| {
        try printShredStats(stdout, agave_cf_code_shred, code_shreds);
    } else {
        try stdout.print("  {s}: missing\n", .{agave_cf_code_shred});
    }
}

fn printProducerStats(stdout: *std.Io.Writer, stats: ProducerStats) !void {
    try stdout.print("producer_walk:\n", .{});
    try stdout.print("  slots: {d}\n", .{stats.slots});
    try stdout.print("  data_packets: {d}\n", .{stats.data_packets});
    try stdout.print("  code_packets: {d}\n", .{stats.code_packets});
    try stdout.print("  total_packets: {d}\n", .{stats.data_packets + stats.code_packets});
    try stdout.print("  payload_bytes: {d}\n", .{stats.payload_bytes});
}

fn printShredStats(stdout: *std.Io.Writer, name: []const u8, stats: ShredStats) !void {
    try stdout.print("  {s}:\n", .{name});
    try stdout.print("    total_packets: {d}\n", .{stats.total_packets});
    try stdout.print("    total_payload_bytes: {d}\n", .{stats.total_payload_bytes});
    try stdout.print("    first_slot: {?d}\n", .{stats.first_slot});
    try stdout.print("    last_slot: {?d}\n", .{stats.last_slot});
    try stdout.print("    max_packet_bytes: {d}\n", .{stats.max_packet_bytes});
    try stdout.print("    oversized_packets: {d}\n", .{stats.oversized_packets});
    try stdout.print("    selected_packets: {d}\n", .{stats.selected_packets});
    try stdout.print("    selected_payload_bytes: {d}\n", .{stats.selected_payload_bytes});
    try stdout.print("    selected_first_slot: {?d}\n", .{stats.selected_first_slot});
    try stdout.print("    selected_last_slot: {?d}\n", .{stats.selected_last_slot});
    try stdout.print("    selected_max_packet_bytes: {d}\n", .{stats.selected_max_packet_bytes});
    try stdout.print("    selected_oversized_packets: {d}\n", .{stats.selected_oversized_packets});
}

fn parseSlotKey(key: []const u8) !Slot {
    if (key.len != 8) return error.InvalidSlotKey;
    return std.mem.readInt(u64, key[0..8], .big);
}

fn writeSlotKey(key: *[8]u8, slot: Slot) void {
    std.mem.writeInt(u64, key, slot, .big);
}

fn parseShredKey(key: []const u8) !ShredKey {
    if (key.len != 16) return error.InvalidShredKey;
    return .{
        .slot = std.mem.readInt(u64, key[0..8], .big),
        .index = std.mem.readInt(u64, key[8..16], .big),
    };
}

fn writeShredKey(key: *[16]u8, shred_key: ShredKey) void {
    std.mem.writeInt(u64, key[0..8], shred_key.slot, .big);
    std.mem.writeInt(u64, key[8..16], shred_key.index, .big);
}

fn slotSelected(config: Config, slot: Slot) bool {
    if (config.start_slot) |start_slot| {
        if (slot < start_slot) return false;
    }
    if (config.end_slot) |end_slot| {
        if (slot > end_slot) return false;
    }
    return true;
}

fn pastEndSlot(config: Config, slot: Slot) bool {
    return if (config.end_slot) |end_slot| slot > end_slot else false;
}

fn minOptional(current: ?Slot, next: Slot) Slot {
    return if (current) |value| @min(value, next) else next;
}

fn maxOptional(current: ?Slot, next: Slot) Slot {
    return if (current) |value| @max(value, next) else next;
}

fn resolveRocksDbPath(allocator: Allocator, ledger_path: []const u8) ![]const u8 {
    const nested_rocksdb_path = try std.fs.path.join(allocator, &.{ ledger_path, "rocksdb" });

    if (isDir(nested_rocksdb_path)) return nested_rocksdb_path;
    allocator.free(nested_rocksdb_path);

    if (!isDir(ledger_path)) {
        std.debug.print("ledger path does not exist or is not a directory: {s}\n", .{ledger_path});
        return error.InvalidLedgerPath;
    }

    return try allocator.dupe(u8, ledger_path);
}

fn isDir(path: []const u8) bool {
    const stat = std.fs.cwd().statFile(path) catch return false;
    return stat.kind == .directory;
}

const ColumnFamilyNames = struct {
    allocator: Allocator,
    names: []const []const u8,

    fn deinit(self: *ColumnFamilyNames) void {
        for (self.names) |name| self.allocator.free(name);
        self.allocator.free(self.names);
    }

    fn contains(self: *const ColumnFamilyNames, name: []const u8) bool {
        for (self.names) |candidate| {
            if (std.mem.eql(u8, candidate, name)) return true;
        }
        return false;
    }
};

fn listColumnFamilies(allocator: Allocator, rocksdb_path: []const u8) !ColumnFamilyNames {
    const options = rocks_c.rocksdb_options_create() orelse return error.RocksDBOptionsCreate;
    defer rocks_c.rocksdb_options_destroy(options);

    const rocksdb_path_z = try allocator.dupeZ(u8, rocksdb_path);
    defer allocator.free(rocksdb_path_z);

    var err_ptr: ?[*:0]u8 = null;
    var count: usize = 0;
    const raw_names = rocks_c.rocksdb_list_column_families(
        options,
        rocksdb_path_z.ptr,
        &count,
        @ptrCast(&err_ptr),
    );
    if (err_ptr) |err_z| {
        defer rocks_c.rocksdb_free(err_z);
        std.debug.print("failed to list RocksDB column families at {s}: {s}\n", .{ rocksdb_path, std.mem.span(err_z) });
        return error.RocksDBListColumnFamilies;
    }
    if (raw_names == null) return error.RocksDBListColumnFamilies;
    defer rocks_c.rocksdb_list_column_families_destroy(raw_names, count);

    const names = try allocator.alloc([]const u8, count);
    errdefer allocator.free(names);

    for (names, raw_names[0..count]) |*name, raw_name| {
        name.* = try allocator.dupe(u8, std.mem.span(raw_name));
    }

    return .{ .allocator = allocator, .names = names };
}

fn requireColumnFamily(available_cfs: *const ColumnFamilyNames, name: []const u8) !void {
    if (available_cfs.contains(name)) return;
    std.debug.print("missing required column family: {s}\n", .{name});
    return error.MissingRequiredColumnFamily;
}

fn columnFamilyDescriptions(
    allocator: Allocator,
    has_code_shred: bool,
) Allocator.Error![]const rocks.ColumnFamilyDescription {
    const count: usize = if (has_code_shred) 4 else 3;
    const cfs = try allocator.alloc(rocks.ColumnFamilyDescription, count);
    cfs[0] = .{ .name = agave_cf_default };
    cfs[1] = .{ .name = agave_cf_meta };
    cfs[2] = .{ .name = agave_cf_data_shred };
    if (has_code_shred) cfs[3] = .{ .name = agave_cf_code_shred };
    return cfs;
}

fn freeOpenedColumnFamilies(allocator: Allocator, column_families: []const rocks.ColumnFamily) void {
    allocator.free(column_families);
}

fn parseArgs(args: []const []const u8) ParseArgsError!ParseResult {
    var config: PartialConfig = .{};
    var seen: std.EnumSet(Arg) = .initEmpty();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const parsed_arg = Arg.parse(arg) orelse {
            if (std.mem.startsWith(u8, arg, "-")) {
                std.debug.print("unknown flag: {s}\n", .{arg});
            } else {
                std.debug.print("unexpected argument: {s}\n", .{arg});
            }
            return error.InvalidArguments;
        };

        if (parsed_arg == .help) return .help;

        if (seen.contains(parsed_arg)) {
            std.debug.print("duplicate argument: {s}\n", .{parsed_arg.name()});
            return error.InvalidArguments;
        }
        seen.insert(parsed_arg);

        switch (parsed_arg) {
            .help => unreachable,
            .ledger => config.ledger = try nextValue(args, &i, parsed_arg.name()),
            .target => config.target = try nextValue(args, &i, parsed_arg.name()),
            .start_slot => config.start_slot = try parseSlot(
                try nextValue(args, &i, parsed_arg.name()),
                parsed_arg.name(),
            ),
            .end_slot => config.end_slot = try parseSlot(
                try nextValue(args, &i, parsed_arg.name()),
                parsed_arg.name(),
            ),
            .rate_hz => config.rate_hz = try parseRateHz(try nextValue(args, &i, parsed_arg.name())),
            .dry_run => config.dry_run = true,
        }
    }

    return .{ .config = try config.finalize() };
}

fn nextValue(args: []const []const u8, index: *usize, flag: []const u8) ParseArgsError![]const u8 {
    if (index.* + 1 >= args.len) {
        std.debug.print("missing value for {s}\n", .{flag});
        return error.InvalidArguments;
    }

    index.* += 1;
    return args[index.*];
}

fn parseSlot(value: []const u8, flag: []const u8) ParseArgsError!Slot {
    return std.fmt.parseUnsigned(Slot, value, 10) catch {
        std.debug.print("invalid slot for {s}: {s}\n", .{ flag, value });
        return error.InvalidArguments;
    };
}

fn parseRateHz(value: []const u8) ParseArgsError!f64 {
    const rate_hz = std.fmt.parseFloat(f64, value) catch {
        std.debug.print("invalid rate for --rate-hz: {s}\n", .{value});
        return error.InvalidArguments;
    };

    if (!(rate_hz > 0) or !std.math.isFinite(rate_hz)) {
        std.debug.print("--rate-hz must be a finite positive value\n", .{});
        return error.InvalidArguments;
    }

    return rate_hz;
}

fn printHelp() void {
    std.debug.print(
        \\usage: shred-stream --ledger <path> --target <ip:port> [options]
        \\
        \\required:
        \\  --ledger <path>       Agave ledger directory or rocksdb directory
        \\  --target <ip:port>    UDP target, usually 127.0.0.1:8002
        \\
        \\options:
        \\  --start-slot <slot>   First slot to stream
        \\  --end-slot <slot>     Inclusive last slot to stream
        \\  --rate-hz <float>     Maximum packets per second
        \\  --dry-run             Read and print stats without sending UDP
        \\  -h, --help            Print this help
        \\
    , .{});
}

test "parse required arguments" {
    const result = try parseArgs(&.{ "--ledger", "ledger", "--target", "127.0.0.1:8002" });
    const config = result.config;
    try std.testing.expectEqualStrings("ledger", config.ledger);
    try std.testing.expectEqualStrings("127.0.0.1:8002", config.target);
    try std.testing.expectEqual(@as(?Slot, null), config.start_slot);
    try std.testing.expectEqual(@as(?Slot, null), config.end_slot);
    try std.testing.expectEqual(@as(?f64, null), config.rate_hz);
    try std.testing.expect(!config.dry_run);
}

test "parse optional arguments" {
    const result = try parseArgs(&.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--rate-hz",    "100.5",
        "--dry-run",
    });
    const config = result.config;
    try std.testing.expectEqual(@as(?Slot, 10), config.start_slot);
    try std.testing.expectEqual(@as(?Slot, 20), config.end_slot);
    try std.testing.expectEqual(@as(?f64, 100.5), config.rate_hz);
    try std.testing.expect(config.dry_run);
}

test "reject invalid slot range" {
    try std.testing.expectError(error.InvalidArguments, parseArgs(&.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "20",
        "--end-slot",   "10",
    }));
}

test "parse slot key" {
    const key = [_]u8{ 0, 0, 0, 0, 0, 0, 0x04, 0xd2 };
    try std.testing.expectEqual(@as(Slot, 1234), try parseSlotKey(&key));
}

test "write slot key" {
    var key: [8]u8 = undefined;
    writeSlotKey(&key, 1234);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0x04, 0xd2 }, &key);
}

test "reject invalid slot key" {
    try std.testing.expectError(error.InvalidSlotKey, parseSlotKey(&.{ 1, 2, 3 }));
}

test "parse shred key" {
    const key = [_]u8{
        0, 0, 0, 0, 0, 0, 0x04, 0xd2,
        0, 0, 0, 0, 0, 0, 0x16, 0x2e,
    };

    const shred_key = try parseShredKey(&key);
    try std.testing.expectEqual(@as(Slot, 1234), shred_key.slot);
    try std.testing.expectEqual(@as(u64, 5678), shred_key.index);
}

test "write shred key" {
    var key: [16]u8 = undefined;
    writeShredKey(&key, .{ .slot = 1234, .index = 5678 });
    try std.testing.expectEqualSlices(u8, &.{
        0, 0, 0, 0, 0, 0, 0x04, 0xd2,
        0, 0, 0, 0, 0, 0, 0x16, 0x2e,
    }, &key);
}

test "reject invalid shred key" {
    try std.testing.expectError(error.InvalidShredKey, parseShredKey(&.{ 1, 2, 3 }));
}

test "slot selected respects optional bounds" {
    const base: Config = .{ .ledger = "ledger", .target = "127.0.0.1:8002" };
    try std.testing.expect(slotSelected(base, 10));

    var bounded = base;
    bounded.start_slot = 10;
    bounded.end_slot = 20;
    try std.testing.expect(!slotSelected(bounded, 9));
    try std.testing.expect(slotSelected(bounded, 10));
    try std.testing.expect(slotSelected(bounded, 20));
    try std.testing.expect(!slotSelected(bounded, 21));
}

test "past end slot respects optional end bound" {
    const base: Config = .{ .ledger = "ledger", .target = "127.0.0.1:8002" };
    try std.testing.expect(!pastEndSlot(base, 100));

    var bounded = base;
    bounded.end_slot = 20;
    try std.testing.expect(!pastEndSlot(bounded, 20));
    try std.testing.expect(pastEndSlot(bounded, 21));
}

test "resolve nested rocksdb path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("ledger/rocksdb");

    const ledger_path = try tmp.dir.realpathAlloc(std.testing.allocator, "ledger");
    defer std.testing.allocator.free(ledger_path);

    const rocksdb_path = try resolveRocksDbPath(std.testing.allocator, ledger_path);
    defer std.testing.allocator.free(rocksdb_path);

    const expected = try tmp.dir.realpathAlloc(std.testing.allocator, "ledger/rocksdb");
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, rocksdb_path);
}

test "resolve direct rocksdb path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("rocksdb");

    const direct_path = try tmp.dir.realpathAlloc(std.testing.allocator, "rocksdb");
    defer std.testing.allocator.free(direct_path);

    const rocksdb_path = try resolveRocksDbPath(std.testing.allocator, direct_path);
    defer std.testing.allocator.free(rocksdb_path);

    try std.testing.expectEqualStrings(direct_path, rocksdb_path);
}
