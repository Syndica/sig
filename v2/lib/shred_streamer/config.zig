const std = @import("std");
const lib = @import("lib");

pub const Slot = lib.solana.Slot;

/// Direction for iterating through the blockstore. Decoupled from rocksdb
/// so this type can live in lib without a rocksdb dependency.
pub const Direction = enum { forward, reverse };

pub const TestMode = enum {
    linear,
    reverse,
    shuffle_global,
    shuffle_slot,
    drop,
    late,
    duplicate,
    corrupt,

    pub fn parse(raw: []const u8) ?TestMode {
        inline for (@typeInfo(TestMode).@"enum".fields) |e_field| {
            if (std.mem.eql(u8, kebabify(e_field.name), raw)) return @enumFromInt(e_field.value);
        }
        return null;
    }

    pub fn modeName(self: TestMode) []const u8 {
        return switch (self) {
            inline else => |itag| kebabify(@tagName(itag)),
        };
    }

    pub fn usesSelectedShreds(self: TestMode) bool {
        return switch (self) {
            .drop, .late, .duplicate, .corrupt => true,
            .linear, .reverse, .shuffle_global, .shuffle_slot => false,
        };
    }
};

/// Converts a snake_case identifier to kebab-case at comptime.
/// Used for parsing kebab-case CLI values into snake_case enum fields.
inline fn kebabify(comptime str: []const u8) []const u8 {
    comptime {
        var kebab = str[0..].*;
        std.mem.replaceScalar(u8, &kebab, '_', '-');
        const copy = kebab;
        return &copy;
    }
}

pub const ShredKindFilter = enum {
    any,
    data,
    code,

    pub fn parse(raw: []const u8) ?ShredKindFilter {
        return std.meta.stringToEnum(ShredKindFilter, raw);
    }

    pub fn kindName(self: ShredKindFilter) []const u8 {
        return @tagName(self);
    }

    pub fn matches(self: ShredKindFilter, kind: ShredKind) bool {
        return switch (self) {
            .any => true,
            .data => kind == .data,
            .code => kind == .code,
        };
    }
};

pub const ShredKind = enum(u8) {
    data,
    code,

    pub fn columnFamilyName(kind: ShredKind) []const u8 {
        return switch (kind) {
            .data => agave_cf_data_shred,
            .code => agave_cf_code_shred,
        };
    }
};

pub const Config = struct {
    ledger: []const u8,
    target: ?[]const u8 = null,
    start_slot: ?Slot = null,
    end_slot: ?Slot = null,
    rate_hz: ?f64 = null,
    test_mode: TestMode = .linear,
    seed: ?u64 = null,
    selected_count: usize = 1,
    shred_kind: ShredKindFilter = .any,
    plan_limit: usize = 20,
    corrupt_bytes: usize = 1,
    dry_run: bool = false,

    pub fn slotSelected(self: Config, slot: Slot) bool {
        if (self.start_slot) |start_slot| {
            if (slot < start_slot) return false;
        }
        return !self.pastEndSlot(slot);
    }

    pub fn pastEndSlot(self: Config, slot: Slot) bool {
        return if (self.end_slot) |end_slot| slot > end_slot else false;
    }

    pub fn pastSlotRange(
        self: Config,
        slot: Slot,
        comptime direction: Direction,
    ) bool {
        return switch (direction) {
            .forward => self.pastEndSlot(slot),
            .reverse => if (self.start_slot) |start_slot| slot < start_slot else false,
        };
    }
};

pub const PartialConfig = struct {
    ledger: ?[]const u8 = null,
    target: ?[]const u8 = null,
    start_slot: ?Slot = null,
    end_slot: ?Slot = null,
    rate_hz: ?f64 = null,
    test_mode: TestMode = .linear,
    seed: ?u64 = null,
    selected_count: ?usize = null,
    shred_kind: ?ShredKindFilter = null,
    plan_limit: ?usize = null,
    corrupt_bytes: ?usize = null,
    dry_run: bool = false,

    pub fn finalize(self: PartialConfig, err_writer: *std.Io.Writer) ParseArgsError!Config {
        const ledger = self.ledger orelse {
            try err_writer.print("missing required argument: --ledger <path>\n", .{});
            return error.InvalidArguments;
        };
        // --target is optional: only needed by the legacy UDP path (legacyMain),
        // not by the v2 service which writes directly to the IPC ring.
        const target = self.target;

        if (self.start_slot != null and
            self.end_slot != null and
            self.end_slot.? < self.start_slot.?)
        {
            try err_writer.print("--end-slot must be greater than or equal to --start-slot\n", .{});
            return error.InvalidArguments;
        }

        switch (self.test_mode) {
            .linear, .reverse => {
                if (self.seed != null) {
                    try err_writer.print(
                        "--seed is only valid with --test-mode shuffle-global, " ++
                            "shuffle-slot, drop, late, duplicate, or corrupt\n",
                        .{},
                    );
                    return error.InvalidArguments;
                }
            },
            .shuffle_global, .shuffle_slot, .drop, .late, .duplicate, .corrupt => {
                if (self.seed == null) {
                    try err_writer.print(
                        "--test-mode {s} requires --seed\n",
                        .{self.test_mode.modeName()},
                    );
                    return error.InvalidArguments;
                }
                if (self.start_slot == null or self.end_slot == null) {
                    try err_writer.print(
                        "--test-mode {s} requires both --start-slot and --end-slot\n",
                        .{self.test_mode.modeName()},
                    );
                    return error.InvalidArguments;
                }
            },
        }

        if (!self.test_mode.usesSelectedShreds()) {
            if (self.selected_count != null) {
                try err_writer.print(
                    "--count is only valid with --test-mode drop, late, duplicate, or corrupt\n",
                    .{},
                );
                return error.InvalidArguments;
            }
            if (self.shred_kind != null) {
                try err_writer.print(
                    "--shred-kind is only valid with --test-mode drop, late, " ++
                        "duplicate, or corrupt\n",
                    .{},
                );
                return error.InvalidArguments;
            }
            if (self.plan_limit != null) {
                try err_writer.print(
                    "--plan-limit is only valid with --test-mode drop, late, " ++
                        "duplicate, or corrupt\n",
                    .{},
                );
                return error.InvalidArguments;
            }
            if (self.corrupt_bytes != null) {
                try err_writer.print(
                    "--corrupt-bytes is only valid with --test-mode corrupt\n",
                    .{},
                );
                return error.InvalidArguments;
            }
        } else if (self.test_mode != .corrupt and self.corrupt_bytes != null) {
            try err_writer.print("--corrupt-bytes is only valid with --test-mode corrupt\n", .{});
            return error.InvalidArguments;
        }

        return .{
            .ledger = ledger,
            .target = target,
            .start_slot = self.start_slot,
            .end_slot = self.end_slot,
            .rate_hz = self.rate_hz,
            .test_mode = self.test_mode,
            .seed = self.seed,
            .selected_count = self.selected_count orelse 1,
            .shred_kind = self.shred_kind orelse .any,
            .plan_limit = self.plan_limit orelse 20,
            .corrupt_bytes = self.corrupt_bytes orelse 1,
            .dry_run = self.dry_run,
        };
    }
};

pub const ParseResult = union(enum) {
    config: Config,
    help,
};

pub const ParseArgsError = error{
    InvalidArguments,
    WriteFailed,
};

pub const Arg = enum {
    help,
    ledger,
    target,
    start_slot,
    end_slot,
    rate_hz,
    test_mode,
    seed,
    count,
    shred_kind,
    plan_limit,
    corrupt_bytes,
    dry_run,

    pub fn parse(raw: []const u8) ?Arg {
        if (std.mem.eql(u8, raw, "--help") or std.mem.eql(u8, raw, "-h")) return .help;
        if (std.mem.eql(u8, raw, "--ledger")) return .ledger;
        if (std.mem.eql(u8, raw, "--target")) return .target;
        if (std.mem.eql(u8, raw, "--start-slot")) return .start_slot;
        if (std.mem.eql(u8, raw, "--end-slot")) return .end_slot;
        if (std.mem.eql(u8, raw, "--rate-hz")) return .rate_hz;
        if (std.mem.eql(u8, raw, "--test-mode")) return .test_mode;
        if (std.mem.eql(u8, raw, "--seed")) return .seed;
        if (std.mem.eql(u8, raw, "--count")) return .count;
        if (std.mem.eql(u8, raw, "--shred-kind")) return .shred_kind;
        if (std.mem.eql(u8, raw, "--plan-limit")) return .plan_limit;
        if (std.mem.eql(u8, raw, "--corrupt-bytes")) return .corrupt_bytes;
        if (std.mem.eql(u8, raw, "--dry-run")) return .dry_run;
        return null;
    }

    pub fn flagName(arg: Arg) []const u8 {
        return switch (arg) {
            .help => "--help",
            .ledger => "--ledger",
            .target => "--target",
            .start_slot => "--start-slot",
            .end_slot => "--end-slot",
            .rate_hz => "--rate-hz",
            .test_mode => "--test-mode",
            .seed => "--seed",
            .count => "--count",
            .shred_kind => "--shred-kind",
            .plan_limit => "--plan-limit",
            .corrupt_bytes => "--corrupt-bytes",
            .dry_run => "--dry-run",
        };
    }
};

// --- Constants ---

pub const agave_cf_default = "default";
pub const agave_cf_meta = "meta";
pub const agave_cf_data_shred = "data_shred";
pub const agave_cf_code_shred = "code_shred";
pub const max_shred_packet_bytes: usize = 1232;
pub const producer_publish_packets: usize = 32;
pub const stream_queue_packets = 8192;
pub const no_current_slot = std.math.maxInt(Slot);

// --- Arg parsing functions ---

pub fn parseArgs(err_writer: *std.Io.Writer, args: []const []const u8) ParseArgsError!ParseResult {
    var config: PartialConfig = .{};
    var seen: std.EnumSet(Arg) = .initEmpty();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const parsed_arg = Arg.parse(arg) orelse {
            if (std.mem.startsWith(u8, arg, "-")) {
                try err_writer.print("unknown flag: {s}\n", .{arg});
            } else {
                try err_writer.print("unexpected argument: {s}\n", .{arg});
            }
            return error.InvalidArguments;
        };

        if (parsed_arg == .help) return .help;

        if (seen.contains(parsed_arg)) {
            try err_writer.print("duplicate argument: {s}\n", .{parsed_arg.flagName()});
            return error.InvalidArguments;
        }
        seen.insert(parsed_arg);

        switch (parsed_arg) {
            .help => unreachable,
            .ledger => config.ledger = try nextValue(err_writer, args, &i, parsed_arg.flagName()),
            .target => config.target = try nextValue(err_writer, args, &i, parsed_arg.flagName()),
            .start_slot => config.start_slot = try parseSlot(
                err_writer,
                try nextValue(err_writer, args, &i, parsed_arg.flagName()),
                parsed_arg.flagName(),
            ),
            .end_slot => config.end_slot = try parseSlot(
                err_writer,
                try nextValue(err_writer, args, &i, parsed_arg.flagName()),
                parsed_arg.flagName(),
            ),
            .rate_hz => config.rate_hz = try parseRateHz(
                err_writer,
                try nextValue(err_writer, args, &i, parsed_arg.flagName()),
            ),
            .test_mode => config.test_mode = try parseTestMode(
                err_writer,
                try nextValue(err_writer, args, &i, parsed_arg.flagName()),
            ),
            .seed => config.seed = try parseSeed(
                err_writer,
                try nextValue(err_writer, args, &i, parsed_arg.flagName()),
            ),
            .count => config.selected_count = try parseSelectedCount(
                err_writer,
                try nextValue(err_writer, args, &i, parsed_arg.flagName()),
            ),
            .shred_kind => config.shred_kind = try parseShredKind(
                err_writer,
                try nextValue(err_writer, args, &i, parsed_arg.flagName()),
            ),
            .plan_limit => config.plan_limit = try parsePlanLimit(
                err_writer,
                try nextValue(err_writer, args, &i, parsed_arg.flagName()),
            ),
            .corrupt_bytes => config.corrupt_bytes = try parseCorruptBytes(
                err_writer,
                try nextValue(err_writer, args, &i, parsed_arg.flagName()),
            ),
            .dry_run => config.dry_run = true,
        }
    }

    return .{ .config = try config.finalize(err_writer) };
}

fn nextValue(
    err_writer: *std.Io.Writer,
    args: []const []const u8,
    index: *usize,
    flag: []const u8,
) ParseArgsError![]const u8 {
    if (index.* + 1 >= args.len) {
        try err_writer.print("missing value for {s}\n", .{flag});
        return error.InvalidArguments;
    }

    index.* += 1;
    return args[index.*];
}

fn parseSlot(err_writer: *std.Io.Writer, value: []const u8, flag: []const u8) ParseArgsError!Slot {
    return std.fmt.parseUnsigned(Slot, value, 10) catch {
        try err_writer.print("invalid slot for {s}: {s}\n", .{ flag, value });
        return error.InvalidArguments;
    };
}

fn parseRateHz(err_writer: *std.Io.Writer, value: []const u8) ParseArgsError!f64 {
    const rate_hz = std.fmt.parseFloat(f64, value) catch {
        try err_writer.print("invalid rate for --rate-hz: {s}\n", .{value});
        return error.InvalidArguments;
    };

    if (!(rate_hz > 0) or !std.math.isFinite(rate_hz)) {
        try err_writer.print("--rate-hz must be a finite positive value\n", .{});
        return error.InvalidArguments;
    }

    return rate_hz;
}

fn parseTestMode(err_writer: *std.Io.Writer, value: []const u8) ParseArgsError!TestMode {
    return TestMode.parse(value) orelse {
        try err_writer.print("invalid test mode for --test-mode: {s}\n", .{value});
        try err_writer.print(
            "valid test modes: linear, reverse, shuffle-global, shuffle-slot, drop, late, " ++
                "duplicate, corrupt\n",
            .{},
        );
        return error.InvalidArguments;
    };
}

fn parseSeed(err_writer: *std.Io.Writer, value: []const u8) ParseArgsError!u64 {
    if (std.mem.startsWith(u8, value, "0x") or std.mem.startsWith(u8, value, "0X")) {
        return std.fmt.parseUnsigned(u64, value[2..], 16) catch {
            try err_writer.print("invalid seed for --seed: {s}\n", .{value});
            return error.InvalidArguments;
        };
    }

    return std.fmt.parseUnsigned(u64, value, 10) catch {
        try err_writer.print("invalid seed for --seed: {s}\n", .{value});
        return error.InvalidArguments;
    };
}

fn parseSelectedCount(err_writer: *std.Io.Writer, value: []const u8) ParseArgsError!usize {
    const selected_count = std.fmt.parseUnsigned(usize, value, 10) catch {
        try err_writer.print("invalid count for --count: {s}\n", .{value});
        return error.InvalidArguments;
    };
    if (selected_count == 0) {
        try err_writer.print("--count must be greater than zero\n", .{});
        return error.InvalidArguments;
    }
    return selected_count;
}

fn parseShredKind(err_writer: *std.Io.Writer, value: []const u8) ParseArgsError!ShredKindFilter {
    return ShredKindFilter.parse(value) orelse {
        try err_writer.print("invalid shred kind for --shred-kind: {s}\n", .{value});
        try err_writer.print("valid shred kinds: any, data, code\n", .{});
        return error.InvalidArguments;
    };
}

fn parsePlanLimit(err_writer: *std.Io.Writer, value: []const u8) ParseArgsError!usize {
    return std.fmt.parseUnsigned(usize, value, 10) catch {
        try err_writer.print("invalid limit for --plan-limit: {s}\n", .{value});
        return error.InvalidArguments;
    };
}

fn parseCorruptBytes(err_writer: *std.Io.Writer, value: []const u8) ParseArgsError!usize {
    const corrupt_bytes = std.fmt.parseUnsigned(usize, value, 10) catch {
        try err_writer.print("invalid byte count for --corrupt-bytes: {s}\n", .{value});
        return error.InvalidArguments;
    };
    if (corrupt_bytes == 0) {
        try err_writer.print("--corrupt-bytes must be greater than zero\n", .{});
        return error.InvalidArguments;
    }
    return corrupt_bytes;
}

pub fn printHelp(stdout: *std.Io.Writer) !void {
    try stdout.print(
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
        \\  --test-mode <mode>    linear, reverse, shuffle-global, shuffle-slot, drop, late, duplicate, or corrupt
        \\  --seed <seed>         Decimal or 0x-prefixed seed for randomized test modes
        \\  --count <n>           Number of selected shreds for selected-shred modes (default: 1)
        \\  --shred-kind <kind>   any, data, or code shreds for selected-shred modes (default: any)
        \\  --plan-limit <n>      Maximum affected slots to preview for selected-shred modes (default: 20)
        \\  --corrupt-bytes <n>   Packet bytes to flip per selected shred in corrupt mode (default: 1)
        \\  --dry-run             Read and print stats without sending UDP
        \\  -h, --help            Print this help
        \\
    , .{});
}

// --- Shared data types ---

pub const ShredKey = struct {
    slot: Slot,
    index: u64,
};

pub const ShredRef = struct {
    slot: Slot,
    index: u64,
    kind: ShredKind,

    pub fn key(self: ShredRef) ShredKey {
        return .{ .slot = self.slot, .index = self.index };
    }
};

pub const RefSchedule = struct {
    refs: std.ArrayList(ShredRef) = .empty,
    selected_slots: u64 = 0,

    pub fn deinit(self: *RefSchedule, allocator: std.mem.Allocator) void {
        self.refs.deinit(allocator);
    }
};

pub const SelectedShredPlan = struct {
    schedule: RefSchedule = .{},
    selected_ref_indices: std.ArrayList(usize) = .empty,
    eligible_shreds: usize = 0,

    pub fn deinit(self: *SelectedShredPlan, allocator: std.mem.Allocator) void {
        self.selected_ref_indices.deinit(allocator);
        self.schedule.deinit(allocator);
    }
};

pub const SelectedShredAction = enum {
    skip,
    send_twice,
    send_corrupt,

    pub fn fromTestMode(test_mode: TestMode) SelectedShredAction {
        return switch (test_mode) {
            .drop, .late => .skip,
            .duplicate => .send_twice,
            .corrupt => .send_corrupt,
            .linear, .reverse, .shuffle_global, .shuffle_slot => unreachable,
        };
    }
};

pub const ProducerStats = struct {
    slots: u64 = 0,
    data_packets: u64 = 0,
    code_packets: u64 = 0,
    payload_bytes: u64 = 0,

    pub fn recordSlot(self: *ProducerStats) void {
        self.slots += 1;
    }

    pub fn recordPacket(self: *ProducerStats, kind: ShredKind, payload_len: usize) void {
        switch (kind) {
            .data => self.data_packets += 1,
            .code => self.code_packets += 1,
        }
        self.payload_bytes += @intCast(payload_len);
    }
};

pub const ProducerProgress = struct {
    current_slot: std.atomic.Value(Slot) = .init(no_current_slot),
    slots: std.atomic.Value(u64) = .init(0),
    data_packets: std.atomic.Value(u64) = .init(0),
    code_packets: std.atomic.Value(u64) = .init(0),
    payload_bytes: std.atomic.Value(u64) = .init(0),
    full_polls: std.atomic.Value(u64) = .init(0),

    pub fn store(self: *ProducerProgress, stats: ProducerStats) void {
        self.slots.store(stats.slots, .release);
        self.data_packets.store(stats.data_packets, .release);
        self.code_packets.store(stats.code_packets, .release);
        self.payload_bytes.store(stats.payload_bytes, .release);
    }
};

pub const SlotStats = struct {
    total: u64 = 0,
    selected: u64 = 0,
    first: ?Slot = null,
    last: ?Slot = null,
    selected_first: ?Slot = null,
    selected_last: ?Slot = null,

    pub fn record(self: *SlotStats, slot: Slot, selected: bool) void {
        self.total += 1;
        self.first = if (self.first) |first| @min(first, slot) else slot;
        self.last = if (self.last) |last| @max(last, slot) else slot;

        if (!selected) return;
        self.selected += 1;
        self.selected_first = if (self.selected_first) |first| @min(first, slot) else slot;
        self.selected_last = if (self.selected_last) |last| @max(last, slot) else slot;
    }
};

pub const ShredStats = struct {
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

    pub fn record(self: *ShredStats, k: ShredKey, packet_len: usize, selected: bool) void {
        self.total_packets += 1;
        self.total_payload_bytes += @intCast(packet_len);
        self.max_packet_bytes = @max(self.max_packet_bytes, packet_len);
        if (packet_len > max_shred_packet_bytes) self.oversized_packets += 1;
        self.first_slot = if (self.first_slot) |first| @min(first, k.slot) else k.slot;
        self.last_slot = if (self.last_slot) |last| @max(last, k.slot) else k.slot;

        if (!selected) return;
        self.selected_packets += 1;
        self.selected_payload_bytes += @intCast(packet_len);
        self.selected_max_packet_bytes = @max(self.selected_max_packet_bytes, packet_len);
        if (packet_len > max_shred_packet_bytes) self.selected_oversized_packets += 1;

        self.selected_first_slot = if (self.selected_first_slot) |first|
            @min(first, k.slot)
        else
            k.slot;

        self.selected_last_slot = if (self.selected_last_slot) |last|
            @max(last, k.slot)
        else
            k.slot;
    }
};

pub const LedgerStats = struct {
    slots: SlotStats,
    data_shreds: ShredStats,
    code_shreds: ?ShredStats,
};

// --- Key serialization ---

pub fn parseSlotKey(k: []const u8) !Slot {
    if (k.len != 8) return error.InvalidSlotKey;
    return std.mem.readInt(u64, k[0..8], .big);
}

pub fn writeSlotKey(k: *[8]u8, slot: Slot) void {
    std.mem.writeInt(u64, k, slot, .big);
}

pub fn parseShredKey(k: []const u8) !ShredKey {
    if (k.len != 16) return error.InvalidShredKey;
    return .{
        .slot = std.mem.readInt(u64, k[0..8], .big),
        .index = std.mem.readInt(u64, k[8..16], .big),
    };
}

pub fn writeShredKey(k: *[16]u8, shred_key: ShredKey) void {
    std.mem.writeInt(u64, k[0..8], shred_key.slot, .big);
    std.mem.writeInt(u64, k[8..16], shred_key.index, .big);
}

// --- Utility functions ---

pub fn consumeSelectedRefIndex(
    selected_ref_indices: []const usize,
    selected_cursor: *usize,
    ref_index: usize,
) bool {
    if (selected_cursor.* >= selected_ref_indices.len) return false;
    if (selected_ref_indices[selected_cursor.*] != ref_index) return false;
    selected_cursor.* += 1;
    return true;
}

pub fn countEligibleShreds(refs: []const ShredRef, shred_kind: ShredKindFilter) usize {
    var count: usize = 0;
    for (refs) |shred_ref| {
        if (shred_kind.matches(shred_ref.kind)) count += 1;
    }
    return count;
}

pub fn chooseSelectedRefIndices(
    allocator: std.mem.Allocator,
    err_writer: *std.Io.Writer,
    refs: []const ShredRef,
    shred_kind: ShredKindFilter,
    count: usize,
    seed: u64,
) !std.ArrayList(usize) {
    var candidates: std.ArrayList(usize) = .empty;
    errdefer candidates.deinit(allocator);

    for (refs, 0..) |shred_ref, ref_index| {
        if (shred_kind.matches(shred_ref.kind)) {
            try candidates.append(allocator, ref_index);
        }
    }

    if (count > candidates.items.len) {
        try err_writer.print(
            "--count {d} exceeds {d} eligible {s} shreds\n",
            .{ count, candidates.items.len, shred_kind.kindName() },
        );
        return error.InvalidSelectedShredCount;
    }

    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().shuffleWithIndex(usize, candidates.items, u64);
    candidates.shrinkRetainingCapacity(count);
    std.mem.sortUnstable(usize, candidates.items, {}, std.sort.asc(usize));
    return candidates;
}

pub fn corruptPacketBytes(packet_data: []u8, corrupt_bytes: usize, random: std.Random) !void {
    if (corrupt_bytes > packet_data.len) return error.CorruptBytesExceedPacket;

    var indices: [max_shred_packet_bytes]usize = undefined;
    for (indices[0..packet_data.len], 0..) |*index, value| {
        index.* = value;
    }
    random.shuffleWithIndex(usize, indices[0..packet_data.len], u64);

    for (indices[0..corrupt_bytes]) |index| {
        const bit_index: u3 = @intCast(random.uintLessThan(u8, 8));
        packet_data[index] ^= @as(u8, 1) << bit_index;
    }
}

// --- Path resolution ---

/// Resolves an Agave ledger path to the actual RocksDB directory.
///
/// Agave ledger layouts have RocksDB either at `<ledger>/rocksdb` (nested) or
/// directly at `<ledger>`. This tries the nested path first, then falls back
/// to the direct path. Returns an owned string that must be freed by the
/// caller.
pub fn resolveRocksDbPath(allocator: std.mem.Allocator, ledger_path: []const u8) ![]const u8 {
    const nested_rocksdb_path = try std.fs.path.join(allocator, &.{ ledger_path, "rocksdb" });

    if (std.fs.cwd().statFile(nested_rocksdb_path)) |stat| {
        if (stat.kind == .directory) return nested_rocksdb_path;
    } else |_| {}
    allocator.free(nested_rocksdb_path);

    if (std.fs.cwd().statFile(ledger_path)) |stat| {
        if (stat.kind == .directory) return try allocator.dupe(u8, ledger_path);
    } else |_| {}

    return error.InvalidLedgerPath;
}

// --- Tests ---

var discarding: std.Io.Writer.Discarding = .init(&.{});

test "parse arguments" {
    {
        const result = try parseArgs(
            &discarding.writer,
            &.{ "--ledger", "ledger", "--target", "127.0.0.1:8002" },
        );
        const config = result.config;
        try std.testing.expectEqualStrings("ledger", config.ledger);
        try std.testing.expectEqualStrings("127.0.0.1:8002", config.target.?);
        try std.testing.expectEqual(@as(?Slot, null), config.start_slot);
        try std.testing.expectEqual(@as(?Slot, null), config.end_slot);
        try std.testing.expectEqual(@as(?f64, null), config.rate_hz);
        try std.testing.expectEqual(.linear, config.test_mode);
        try std.testing.expectEqual(@as(?u64, null), config.seed);
        try std.testing.expectEqual(@as(usize, 1), config.selected_count);
        try std.testing.expectEqual(.any, config.shred_kind);
        try std.testing.expectEqual(@as(usize, 20), config.plan_limit);
        try std.testing.expect(!config.dry_run);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--rate-hz",    "100.5",
            "--test-mode",  "reverse",
            "--dry-run",
        });
        const config = result.config;
        try std.testing.expectEqual(@as(?Slot, 10), config.start_slot);
        try std.testing.expectEqual(@as(?Slot, 20), config.end_slot);
        try std.testing.expectEqual(@as(?f64, 100.5), config.rate_hz);
        try std.testing.expectEqual(.reverse, config.test_mode);
        try std.testing.expectEqual(@as(?u64, null), config.seed);
        try std.testing.expect(config.dry_run);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",    "ledger",
            "--target",    "127.0.0.1:8002",
            "--test-mode", "linear",
        });
        try std.testing.expectEqual(.linear, result.config.test_mode);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "shuffle-global",
            "--seed",       "0xdeadbeef",
        });
        try std.testing.expectEqual(.shuffle_global, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 0xdeadbeef), result.config.seed);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "shuffle-global",
            "--seed",       "12345",
        });
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "shuffle-slot",
            "--seed",       "12345",
        });
        try std.testing.expectEqual(.shuffle_slot, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "drop",
            "--seed",       "12345",
        });
        try std.testing.expectEqual(.drop, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
        try std.testing.expectEqual(@as(usize, 1), result.config.selected_count);
        try std.testing.expectEqual(.any, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 20), result.config.plan_limit);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "drop",
            "--seed",       "12345",
            "--count",      "2",
            "--shred-kind", "code",
            "--plan-limit", "5",
        });
        try std.testing.expectEqual(.drop, result.config.test_mode);
        try std.testing.expectEqual(@as(usize, 2), result.config.selected_count);
        try std.testing.expectEqual(.code, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 5), result.config.plan_limit);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "late",
            "--seed",       "12345",
            "--count",      "3",
            "--shred-kind", "data",
            "--plan-limit", "0",
        });
        try std.testing.expectEqual(.late, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
        try std.testing.expectEqual(@as(usize, 3), result.config.selected_count);
        try std.testing.expectEqual(.data, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 0), result.config.plan_limit);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "duplicate",
            "--seed",       "12345",
            "--count",      "4",
            "--shred-kind", "any",
            "--plan-limit", "7",
        });
        try std.testing.expectEqual(.duplicate, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
        try std.testing.expectEqual(@as(usize, 4), result.config.selected_count);
        try std.testing.expectEqual(.any, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 7), result.config.plan_limit);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",        "ledger",
            "--target",        "127.0.0.1:8002",
            "--start-slot",    "10",
            "--end-slot",      "20",
            "--test-mode",     "corrupt",
            "--seed",          "12345",
            "--count",         "4",
            "--shred-kind",    "data",
            "--plan-limit",    "7",
            "--corrupt-bytes", "3",
        });
        try std.testing.expectEqual(.corrupt, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
        try std.testing.expectEqual(@as(usize, 4), result.config.selected_count);
        try std.testing.expectEqual(.data, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 7), result.config.plan_limit);
        try std.testing.expectEqual(@as(usize, 3), result.config.corrupt_bytes);
    }

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "shuffle-global",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "shuffle-global",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "shuffle-slot",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "shuffle-slot",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "drop",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "late",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "duplicate",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "corrupt",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "drop",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "late",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "duplicate",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "corrupt",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--seed",       "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--count",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--shred-kind", "data",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--plan-limit", "5",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",        "ledger",
        "--target",        "127.0.0.1:8002",
        "--start-slot",    "10",
        "--end-slot",      "20",
        "--corrupt-bytes", "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "reverse",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--test-mode",  "drop",
        "--seed",       "1",
        "--count",      "0",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--test-mode",  "drop",
        "--seed",       "1",
        "--shred-kind", "bad-kind",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--test-mode",  "drop",
        "--seed",       "1",
        "--plan-limit", "not-a-limit",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",        "ledger",
        "--target",        "127.0.0.1:8002",
        "--start-slot",    "10",
        "--end-slot",      "20",
        "--test-mode",     "drop",
        "--seed",          "1",
        "--corrupt-bytes", "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",        "ledger",
        "--target",        "127.0.0.1:8002",
        "--start-slot",    "10",
        "--end-slot",      "20",
        "--test-mode",     "corrupt",
        "--seed",          "1",
        "--corrupt-bytes", "0",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",        "ledger",
        "--target",        "127.0.0.1:8002",
        "--start-slot",    "10",
        "--end-slot",      "20",
        "--test-mode",     "corrupt",
        "--seed",          "1",
        "--corrupt-bytes", "not-a-count",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--test-mode",  "shuffle-global",
        "--seed",       "not-a-seed",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "20",
        "--end-slot",   "10",
    }));
}

test "choose shred target indices" {
    const allocator = std.testing.allocator;
    const refs = [_]ShredRef{
        .{ .slot = 1, .index = 0, .kind = .data },
        .{ .slot = 1, .index = 1, .kind = .code },
        .{ .slot = 1, .index = 2, .kind = .data },
        .{ .slot = 1, .index = 3, .kind = .code },
        .{ .slot = 1, .index = 4, .kind = .data },
    };

    var first = try chooseSelectedRefIndices(allocator, &discarding.writer, &refs, .data, 2, 12345);
    defer first.deinit(allocator);
    var second = try chooseSelectedRefIndices(
        allocator,
        &discarding.writer,
        &refs,
        .data,
        2,
        12345,
    );
    defer second.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), first.items.len);
    try std.testing.expectEqualSlices(usize, first.items, second.items);
    for (first.items) |index| {
        try std.testing.expect(refs[index].kind == .data);
    }

    var code_result = try chooseSelectedRefIndices(
        allocator,
        &discarding.writer,
        &refs,
        .code,
        2,
        12345,
    );
    defer code_result.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), code_result.items.len);
    for (code_result.items) |index| {
        try std.testing.expect(refs[index].kind == .code);
    }

    try std.testing.expectError(
        error.InvalidSelectedShredCount,
        chooseSelectedRefIndices(allocator, &discarding.writer, &refs, .code, 3, 12345),
    );
}

test "parse and write slot keys" {
    const k = [_]u8{ 0, 0, 0, 0, 0, 0, 0x04, 0xd2 };
    try std.testing.expectEqual(@as(Slot, 1234), try parseSlotKey(&k));

    var written_key: [8]u8 = undefined;
    writeSlotKey(&written_key, 1234);
    try std.testing.expectEqualSlices(u8, &k, &written_key);

    try std.testing.expectError(error.InvalidSlotKey, parseSlotKey(&.{ 1, 2, 3 }));
}

test "parse and write shred keys" {
    const k = [_]u8{
        0, 0, 0, 0, 0, 0, 0x04, 0xd2,
        0, 0, 0, 0, 0, 0, 0x16, 0x2e,
    };

    const shred_key = try parseShredKey(&k);
    try std.testing.expectEqual(@as(Slot, 1234), shred_key.slot);
    try std.testing.expectEqual(@as(u64, 5678), shred_key.index);

    var written_key: [16]u8 = undefined;
    writeShredKey(&written_key, .{ .slot = 1234, .index = 5678 });
    try std.testing.expectEqualSlices(u8, &k, &written_key);

    try std.testing.expectError(error.InvalidShredKey, parseShredKey(&.{ 1, 2, 3 }));
}

test "slot bounds helpers respect optional bounds" {
    const base: Config = .{ .ledger = "ledger" };
    try std.testing.expect(base.slotSelected(10));
    try std.testing.expect(!base.pastEndSlot(100));

    var bounded = base;
    bounded.start_slot = 10;
    bounded.end_slot = 20;
    try std.testing.expect(!bounded.slotSelected(9));
    try std.testing.expect(bounded.slotSelected(10));
    try std.testing.expect(bounded.slotSelected(20));
    try std.testing.expect(!bounded.slotSelected(21));
    try std.testing.expect(!bounded.pastEndSlot(20));
    try std.testing.expect(bounded.pastEndSlot(21));
}

test "resolve rocksdb path" {
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

    const direct_path = try tmp.dir.realpathAlloc(std.testing.allocator, "ledger/rocksdb");
    defer std.testing.allocator.free(direct_path);

    const direct_rocksdb_path = try resolveRocksDbPath(std.testing.allocator, direct_path);
    defer std.testing.allocator.free(direct_rocksdb_path);

    try std.testing.expectEqualStrings(direct_path, direct_rocksdb_path);
}
