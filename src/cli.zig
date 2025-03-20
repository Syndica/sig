const std = @import("std");

pub const CommandHelp = struct {
    short: []const u8,
    long: ?[]const u8,
};

pub fn CommandInfo(comptime S: type) type {
    return struct {
        help: CommandHelp,
        /// Struct with all the same fields as `S`, but: the subcommand union
        /// field type is replaced with struct with all the same fields, but
        /// where each field is of type `CommandInfo(FieldType)`; each option
        /// field type is replaced with `OptionInfo(FieldType)`; each option
        /// group field type is replaced with `OptionInfoGroup(FieldType)`.
        sub: SubInfo,

        pub const Cmd = S;
        pub const SubInfo = computeCmdAndOptBasicInfo(S, null).SubInfo;
    };
}

/// Returns a struct with all the same fields as input struct `S`,
/// but where each field is of type `OptionInfo(FieldType)`.
pub fn OptionInfoGroup(comptime S: type) type {
    const Type = std.builtin.Type;
    const s_info = @typeInfo(S).Struct;

    var sub_fields: [s_info.fields.len]Type.StructField = undefined;
    for (&sub_fields, s_info.fields) |*new_s_field, s_field| {
        if (@typeInfo(s_field.type) == .Union or
            (@typeInfo(s_field.type) == .Optional and
            @typeInfo(@typeInfo(s_field.type).Optional.child) == .Union))
        {
            @compileError("The subcommand field cannot be part of an option group");
        }

        new_s_field.* = .{
            .name = s_field.name,
            .type = OptionInfo(s_field.type),
            .default_value = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{ .Struct = .{
        .layout = .auto,
        .backing_integer = null,
        .fields = &sub_fields,
        .is_tuple = false,
        .decls = &.{},
    } });
}

/// Describes how the value for a `[]const u8` should be interpreted.
pub const BytesConfig = enum {
    /// Should be parsed as a single string value.
    string,
    /// Should be parsed as a list of unsigned 8 bit integers.
    list,

    /// Used in place of `BytesConfig` when `[]const u8` is in an optional or list,
    /// since the only logical thing for such a composite to be would be a string.
    pub const StringOnly = enum { string };
};

pub fn OptionInfo(comptime Opt: type) type {
    return struct {
        /// Used to override the name displayed on the command line, or null
        /// to simply use the associated field name in kebab-case form.
        name_override: ?[]const u8,

        /// The alias associated with this option, or `.none`.
        alias: OptionAlias,

        /// Default value to use for this value.
        default_value: Option,

        /// Options describing how the value(s) should be parsed.
        /// For `Opt = []const T` & `Opt = ?T`, applies to `T`,
        /// except for `T = []const u8`, which would always be
        /// interpeted as a string.
        config: Config,

        /// The help information associated with this option.
        help: []const u8,

        pub const Option = Opt;
        pub const Config = OptionConfig(Option);
    };
}

inline fn isOptionInfo(comptime T: type) bool {
    comptime {
        if (@typeInfo(T) != .Struct) return false;
        if (!@hasDecl(T, "Option")) return false;
        if (@TypeOf(&T.Option) != *const type) return false;
        return OptionInfo(T.Option) == T;
    }
}

fn OptionConfig(comptime Opt: type) type {
    return switch (@typeInfo(Opt)) {
        .Pointer => |p_info| blk: {
            if (p_info.size != .Slice) {
                @compileError("Cannot have non-slice pointer options");
            }

            if (p_info.child == u8) break :blk BytesConfig;
            const SubConfig = OptionConfig(p_info.child);

            // []const []const u8 is always a list of strings
            if (SubConfig == BytesConfig) break :blk BytesConfig.StringOnly;

            break :blk SubConfig;
        },
        .Optional => |o_info| blk: {
            switch (@typeInfo(o_info.child)) {
                .Optional => {
                    @compileError("Cannot have optional optional options");
                },
                .Pointer => |p_info| if (p_info.size == .Slice and p_info.child != u8) {
                    @compileError("Cannot have optional list options;" ++
                        " an unspecified list is simply empty");
                },
                else => {},
            }

            const SubConfig = OptionConfig(o_info.child);

            // ?[]const u8 is always an optional string
            if (SubConfig == BytesConfig) break :blk BytesConfig.StringOnly;

            break :blk SubConfig;
        },
        .Int, .Enum, .Bool => void,
        else => @compileError("Unexpected option type: " ++ @typeName(Opt)),
    };
}

/// Exhaustive enum representing a single alphabetic character,
/// aside from the letter 'h' (`[A-Za-gi-z]`).
pub const OptionAlias = enum(u7) {
    none = 0,
    // zig fmt: off
    a = 'a', A = 'A',
    b = 'b', B = 'B',
    c = 'c', C = 'C',
    d = 'd', D = 'D',
    e = 'e', E = 'E',
    f = 'f', F = 'F',
    g = 'g', G = 'G',
    // zig fmt: on

    // NOTE: exclude 'h' as the reserved help flag.
    // h = 'h',
    H = 'H',

    // zig fmt: off
    i = 'i', I = 'I',
    j = 'j', J = 'J',
    k = 'k', K = 'K',
    l = 'l', L = 'L',
    m = 'm', M = 'M',
    n = 'n', N = 'N',
    o = 'o', O = 'O',
    p = 'p', P = 'P',
    q = 'q', Q = 'Q',
    r = 'r', R = 'R',
    s = 's', S = 'S',
    t = 't', T = 'T',
    u = 'u', U = 'U',
    v = 'v', V = 'V',
    w = 'w', W = 'W',
    x = 'x', X = 'X',
    y = 'y', Y = 'Y',
    z = 'z', Z = 'Z',
    // zig fmt: on

    pub fn from(char: u8) OptionAlias {
        return switch (char) {
            'A'...'Z',
            'a'...('h' - 1),
            ('h' + 1)...'z',
            => |c| @enumFromInt(c),
            else => .none,
        };
    }
};

pub const ParseCmdError = error{
    /// Unrecognized `--{name}`.
    UnrecognizedOptionName,
    /// Unrecognized `-{c}`.
    UnrecognizedOptionAlias,

    /// Unexpected positional in command with no subcommand and not expecting positionals.
    UnexpectedPositional,

    UnrecognizedCommand,
    MissingOptions,
    MissingCommand,
} || ParseOptionKeyMaybeValStrError ||
    ParseSingleOptValueError ||
    std.mem.Allocator.Error ||
    std.os.windows.SetConsoleTextAttributeError; // for the TTY for the help message

pub fn Parser(
    /// Must be a struct type containing zero or more option fields, and zero or one
    /// sub-command fields which is a tagged union (possibly optional) wherein each
    /// member is a sub-command struct following the same description as this one,
    /// recursively.
    ///
    /// An option field must either be a parsed value such as a
    /// boolean, integer, enum, string, or list or optional there-of,
    /// or a struct of parsed values.
    comptime Cmd: type,
    comptime cmd_info: CommandInfo(Cmd),
) type {
    const helper = CmdHelper(Cmd, cmd_info, null);
    return struct {
        /// The caller is responsible for calling `free` on the result.
        /// Returns `null` if the help command is issued; if this happens,
        /// that means the `help_writer` has had the relevant help information
        /// written to it.
        pub fn parse(
            allocator: std.mem.Allocator,
            /// Only used for the help output.
            program_name: []const u8,
            tty_config: std.io.tty.Config,
            /// `std.io.GenericWriter(...)` | `std.io.AnyWriter`
            help_writer: anytype,
            /// Should be a list of commands. If the source is `argv`, it should be `argv[1..]`.
            /// The strings in the list may referenced by the return value of this function.
            args: []const []const u8,
        ) (ParseCmdError || @TypeOf(help_writer).Error)!?Cmd {
            var args_iter: ArgsIter = .{ .args = args, .index = 0 };
            return helper.parseInner(
                allocator,
                &[_][]const u8{program_name},
                tty_config,
                help_writer,
                &args_iter,
            );
        }

        pub fn free(allocator: std.mem.Allocator, cmd: Cmd) void {
            helper.freeImpl(allocator, cmd);
        }
    };
}

fn ParserTester(
    comptime Cmd: type,
    comptime cmd_info: CommandInfo(Cmd),
) type {
    const parser = Parser(Cmd, cmd_info);
    return struct {
        fn expectParsed(
            args: []const []const u8,
            expected: ParseCmdError!?Cmd,
        ) !void {
            const actual = parser.parse(
                std.testing.allocator,
                "irrelevant",
                .no_color,
                std.io.null_writer,
                args,
            );
            defer if (actual) |parsed_or_null| if (parsed_or_null) |parsed_cmd| {
                parser.free(std.testing.allocator, parsed_cmd);
            } else {} else |_| {};

            try std.testing.expectEqualDeep(expected, actual);
        }

        fn expectHelp(
            args: []const []const u8,
            expected: []const u8,
        ) !void {
            for (args) |arg| {
                if (std.mem.eql(u8, arg, "--help")) break;
                if (std.mem.eql(u8, arg, "-h")) break;
            } else std.debug.panic(
                "Missing expected `-h`/`--help` argument in `args`: {s}",
                .{args},
            );

            var actual_help_str: std.ArrayListUnmanaged(u8) = .{};
            defer actual_help_str.deinit(std.testing.allocator);

            try std.testing.expectEqual(null, try parser.parse(
                std.testing.allocator,
                "sig-test",
                .no_color,
                actual_help_str.writer(std.testing.allocator),
                args,
            ));

            try std.testing.expectEqualStrings(expected, actual_help_str.items);
        }
    };
}

test "TestCmd" {
    const TestCmd = struct {
        log_level: std.log.Level,
        metrics_port: u16,
        subcmd: union(enum) {
            identity: Identity,
            gossip: Gossip,
            rpc: Rpc,
        },

        const cmd_info: CommandInfo(@This()) = .{
            .help = .{
                .short = "Test",
                .long = "Test CLI",
            },
            .sub = .{
                .subcmd = .{
                    .identity = Identity.cmd_info,
                    .gossip = Gossip.cmd_info,
                    .rpc = Rpc.cmd_info,
                },
                .log_level = .{
                    .name_override = null,
                    .alias = .l,
                    .default_value = .debug,
                    .config = {},
                    .help = "The amount of detail to log",
                },
                .metrics_port = .{
                    .name_override = null,
                    .alias = .m,
                    .default_value = 12345,
                    .config = {},
                    .help = "The metrics port",
                },
            },
        };

        // structs can be used to share options across commands
        const Shared = struct {
            fizz: u32,
            buzz: []const u64,

            const opt_info: OptionInfoGroup(@This()) = .{
                .fizz = .{
                    .name_override = null,
                    .alias = .f,
                    .default_value = 32,
                    .config = {},
                    .help = "fizzy",
                },
                .buzz = .{
                    .name_override = null,
                    .alias = .b,
                    .help = "buzzy",
                    .config = {},
                    .default_value = &.{},
                },
            };
        };

        const Identity = struct {
            shared: Shared,
            subcmd: ?union(enum) { foo },

            const cmd_info: CommandInfo(@This()) = .{
                .help = .{
                    .short = "Get identity",
                    .long = "Print our cached identity",
                },
                .sub = .{
                    .subcmd = .{
                        .foo = .{
                            .help = .{ .short = "bar", .long = null },
                            .sub = .{},
                        },
                    },
                    .shared = Shared.opt_info,
                },
            };
        };

        const Gossip = struct {
            gossip_port: u16,
            entrypoints: []const []const u8,
            shared: Shared,

            const cmd_info: CommandInfo(@This()) = .{
                .help = .{
                    .short = "Run gossip",
                    .long = "Sub-Test CLI",
                },
                .sub = .{
                    .shared = Shared.opt_info,
                    .gossip_port = .{
                        .name_override = null,
                        .alias = .p,
                        .default_value = 8020,
                        .config = {},
                        .help = "The port to run gossip listener",
                    },
                    .entrypoints = .{
                        .name_override = "entrypoint",
                        .alias = .e,
                        .default_value = &.{},
                        .config = .string,
                        .help = "Gossip address of the entrypoint validators",
                    },
                },
            };
        };

        const Rpc = struct {
            // NOTE: the `default_value` field is requried; optionals are used to be able to represent the "unspecified" state.
            single: ?bool,

            const cmd_info: CommandInfo(@This()) = .{
                .help = .{
                    .short = "Run RPC",
                    .long = null,
                },
                .sub = .{
                    .single = .{
                        .name_override = null,
                        .alias = .none,
                        .default_value = null,
                        .config = {},
                        .help = "A single option",
                    },
                },
            };
        };
    };

    const parser_tester = ParserTester(TestCmd, TestCmd.cmd_info);
    const expectParsed = parser_tester.expectParsed;
    const expectHelp = parser_tester.expectHelp;

    try expectParsed(&.{}, error.MissingCommand);

    try expectParsed(&.{"identity"}, .{
        .log_level = .debug,
        .metrics_port = 12345,
        .subcmd = .{
            .identity = .{
                .shared = .{
                    .fizz = 32,
                    .buzz = &.{},
                },
                .subcmd = null,
            },
        },
    });

    try expectParsed(&.{ "identity", "foo" }, .{
        .log_level = .debug,
        .metrics_port = 12345,
        .subcmd = .{
            .identity = .{
                .shared = .{
                    .fizz = 32,
                    .buzz = &.{},
                },
                .subcmd = .foo,
            },
        },
    });

    try expectParsed(&.{ "--log-level=info", "gossip", "--gossip-port=2", "-e", "33" }, .{
        .log_level = .info,
        .metrics_port = 12345,
        .subcmd = .{
            .gossip = .{
                .gossip_port = 2,
                .entrypoints = &.{"33"},
                .shared = .{
                    .fizz = 32,
                    .buzz = &.{},
                },
            },
        },
    });

    try expectParsed(&.{ "-m", "54321", "gossip", "-e", "33", "--entrypoint=1" }, .{
        .log_level = .debug,
        .metrics_port = 54321,
        .subcmd = .{
            .gossip = .{
                .gossip_port = 8020,
                .entrypoints = &.{ "33", "1" },
                .shared = .{
                    .fizz = 32,
                    .buzz = &.{},
                },
            },
        },
    });

    try expectParsed(&.{ "gossip", "-b=1", "-b=2", "-b=3" }, .{
        .log_level = .debug,
        .metrics_port = 12345,
        .subcmd = .{
            .gossip = .{
                .gossip_port = 8020,
                .entrypoints = &.{},
                .shared = .{
                    .fizz = 32,
                    .buzz = &.{ 1, 2, 3 },
                },
            },
        },
    });

    try expectParsed(&.{"rpc"}, .{
        .log_level = .debug,
        .metrics_port = 12345,
        .subcmd = .{ .rpc = .{ .single = null } },
    });

    try expectParsed(&.{ "rpc", "--single" }, .{
        .log_level = .debug,
        .metrics_port = 12345,
        .subcmd = .{ .rpc = .{ .single = true } },
    });

    try expectParsed(&.{ "rpc", "--single=false" }, .{
        .log_level = .debug,
        .metrics_port = 12345,
        .subcmd = .{ .rpc = .{ .single = false } },
    });

    try expectHelp(&.{"-h"},
        \\USAGE:
        \\  sig-test [OPTIONS]
        \\
        \\Test
        \\
        \\Test CLI
        \\
        \\COMMANDS:
        \\  identity   Get identity
        \\  gossip     Run gossip
        \\  rpc        Run RPC
        \\
        \\OPTIONS:
        \\  -l, --log-level     (default: debug)   The amount of detail to log
        \\  -m, --metrics-port  (default: 12345)   The metrics port
        \\  -h, --help                             Prints help information
        \\
    );

    try expectHelp(&.{ "identity", "--help" },
        \\USAGE:
        \\  sig-test identity [OPTIONS]
        \\
        \\Get identity
        \\
        \\Print our cached identity
        \\
        \\COMMANDS:
        \\  foo   bar
        \\
        \\OPTIONS:
        \\  -f, --fizz  (default: 32)   fizzy
        \\  -b, --buzz                  buzzy
        \\  -h, --help                  Prints help information
        \\
    );

    try expectHelp(&.{ "identity", "foo", "--help" },
        \\USAGE:
        \\  sig-test identity foo [OPTIONS]
        \\
        \\bar
        \\
        \\OPTIONS:
        \\  -h, --help   Prints help information
        \\
    );

    try expectHelp(&.{ "gossip", "--help" },
        \\USAGE:
        \\  sig-test gossip [OPTIONS]
        \\
        \\Run gossip
        \\
        \\Sub-Test CLI
        \\
        \\OPTIONS:
        \\  -p, --gossip-port  (default: 8020)   The port to run gossip listener
        \\  -e, --entrypoint                     Gossip address of the entrypoint validators
        \\  -f, --fizz         (default: 32)     fizzy
        \\  -b, --buzz                           buzzy
        \\  -h, --help                           Prints help information
        \\
    );

    try expectHelp(&.{ "rpc", "-h" },
        \\USAGE:
        \\  sig-test rpc [OPTIONS]
        \\
        \\Run RPC
        \\
        \\OPTIONS:
        \\      --single   A single option
        \\  -h, --help     Prints help information
        \\
    );
}

const ALIAS_TABLE_IDX_BASE = 'A';
const MAX_ALIAS_TABLE_LEN = 'z' + 1 - 'A';

const OptStructIndex = struct {
    index: usize,
    sub: ?usize,
};

fn CmdHelper(
    comptime Cmd: type,
    comptime cmd_info: CommandInfo(Cmd),
    comptime maybe_parent_name: ?[]const u8,
) type {
    @setEvalBranchQuota(10_000);
    const Type = std.builtin.Type;

    const parent_name = maybe_parent_name orelse "root";
    const parent_prefix = parent_name ++ ".";

    const cmd_fields: []const Type.StructField = switch (@typeInfo(Cmd)) {
        .Struct => |cmd_s_info| cmd_s_info.fields,
        .Void => &.{},
        else => unreachable,
    };

    const cmd_and_opt_basic_info = computeCmdAndOptBasicInfo(Cmd, maybe_parent_name);
    const option_count = cmd_and_opt_basic_info.option_count;
    const maybe_sub_cmd_s_field_index = cmd_and_opt_basic_info.maybe_sub_cmd_s_field_index;

    const OptEnumInt = std.math.IntFittingRange(
        0,
        // TODO: this is a hack to get around the troubles with `u0` enums being weird in 0.13
        @max(1, option_count -| 1),
    );
    const OptEnumIntPlusOne = std.math.IntFittingRange(0, option_count);
    const alias_table_sentinel: OptEnumIntPlusOne = option_count;

    const OptEnum: type, //
    const opt_enum_to_field_map: []const OptStructIndex, //
    // WIP table that will be used to construct a final table for mapping aliases to options
    const alias_table_wip: [MAX_ALIAS_TABLE_LEN]OptEnumIntPlusOne, //
    // partially default-initialised result
    const default_init: Cmd //
    = blk: {
        var opt_enum_fields: []const Type.EnumField = &.{};
        var opt_enum_to_field_map: []const OptStructIndex = &.{};

        var alias_table_wip = [_]OptEnumIntPlusOne{alias_table_sentinel} ** MAX_ALIAS_TABLE_LEN;

        var default_init: Cmd = undefined;

        @setEvalBranchQuota(cmd_fields.len * 3 + 1);
        for (cmd_fields, 0..) |s_field, s_field_i| {
            if (@typeInfo(s_field.type) == .Union or
                (@typeInfo(s_field.type) == .Optional and
                @typeInfo(@typeInfo(s_field.type).Optional.child) == .Union))
            {
                continue;
            }

            const maybe_opt_info = @field(cmd_info.sub, s_field.name);
            if (isOptionInfo(@TypeOf(maybe_opt_info))) {
                opt_enum_to_field_map = opt_enum_to_field_map ++ .{.{
                    .index = s_field_i,
                    .sub = null,
                }};
                computeOptFieldInfo(
                    maybe_parent_name,

                    s_field.name,
                    s_field.type,
                    maybe_opt_info,

                    &opt_enum_fields,

                    &default_init,

                    OptEnumIntPlusOne,
                    &alias_table_wip,
                );
                continue;
            }

            // handle `OptionInfoGroup`
            const s_sub_info = @typeInfo(s_field.type).Struct;
            @setEvalBranchQuota(cmd_fields.len * 3 + 1 + s_sub_info.fields.len * 2 + 1);
            for (s_sub_info.fields, 0..) |s_sub_field, s_sub_field_i| {
                opt_enum_to_field_map = opt_enum_to_field_map ++ .{.{
                    .index = s_field_i,
                    .sub = s_sub_field_i,
                }};
                computeOptFieldInfo(
                    maybe_parent_name,

                    s_sub_field.name,
                    s_sub_field.type,
                    @field(maybe_opt_info, s_sub_field.name),

                    &opt_enum_fields,

                    &@field(default_init, s_field.name),

                    OptEnumIntPlusOne,
                    &alias_table_wip,
                );
            }
        }

        const OptEnum = @Type(.{ .Enum = .{
            .tag_type = OptEnumInt,
            .fields = opt_enum_fields,
            .decls = &.{},
            .is_exhaustive = true,
        } });

        break :blk .{
            OptEnum,
            opt_enum_to_field_map,
            alias_table_wip,
            default_init,
        };
    };
    const opt_enum_fields = @typeInfo(OptEnum).Enum.fields;

    // create the subcommand list once at comptime
    // so that we don't have to do two inline loops
    // when printing subcommand help
    const SubCmdNameHelpPair = struct { []const u8, []const u8 };
    const maybe_subcmd_list: ?[]const SubCmdNameHelpPair = blk: {
        const sub_cmd_s_field_index = maybe_sub_cmd_s_field_index orelse break :blk null;

        const sub_cmd_s_field_info = cmd_fields[sub_cmd_s_field_index];
        const sub_cmd_s_field_name = sub_cmd_s_field_info.name;
        const CmdMaybeUnion = sub_cmd_s_field_info.type;

        const CmdUnion = switch (@typeInfo(CmdMaybeUnion)) {
            .Union => CmdMaybeUnion,
            .Optional => |o_info| o_info.child,
            else => unreachable,
        };
        const u_info = @typeInfo(CmdUnion).Union;

        var subcmd_list: [u_info.fields.len]SubCmdNameHelpPair = undefined;
        @setEvalBranchQuota(u_info.fields.len * 3 + 1);
        for (
            &subcmd_list,
            u_info.fields,
        ) |*name_help_pair, u_field| {
            const kebab_name = comptimeReplaceScalar(u_field.name, '_', '-');
            const SubCmd = u_field.type;
            const sub_cmd_info: CommandInfo(SubCmd) =
                @field(@field(cmd_info.sub, sub_cmd_s_field_name), u_field.name);
            name_help_pair.* = .{ kebab_name, sub_cmd_info.help.short };
        }

        break :blk &subcmd_list ++ .{};
    };

    const alias_table_len: usize, //
    const alias_table_has_holes: bool //
    = alias_info: {
        if (opt_enum_fields.len == 0) break :alias_info .{ 0, false };

        const OptEnumIntVec = @Vector(MAX_ALIAS_TABLE_LEN, OptEnumIntPlusOne);
        const sentinel_vec: OptEnumIntVec = @splat(alias_table_sentinel);
        const used_aliases_mask_vec = alias_table_wip != sentinel_vec;

        const UsedAliasesBits = @Type(.{ .Int = .{
            .signedness = .unsigned,
            .bits = MAX_ALIAS_TABLE_LEN,
        } });
        const used_aliases_bits: UsedAliasesBits = @bitCast(used_aliases_mask_vec);
        const trailing_unused_bits = @clz(used_aliases_bits);

        const alias_table_len = MAX_ALIAS_TABLE_LEN - trailing_unused_bits;
        const alias_table_has_holes = @popCount(used_aliases_bits) == alias_table_len;
        break :alias_info .{
            alias_table_len,
            alias_table_has_holes,
        };
    };

    const alias_table: [alias_table_len]OptEnumIntPlusOne = alias_table_wip[0..alias_table_len].*;

    return struct {
        fn freeImpl(allocator: std.mem.Allocator, args: Cmd) void {
            freeOptions(allocator, args);
            const sub_cmd_s_field_index = maybe_sub_cmd_s_field_index orelse return;

            const sub_cmd_s_field_info = cmd_fields[sub_cmd_s_field_index];
            const sub_cmd_s_field_name = sub_cmd_s_field_info.name;
            const CmdMaybeUnion = sub_cmd_s_field_info.type;

            const sub_cmd_info_map = @field(cmd_info.sub, sub_cmd_s_field_name);
            const is_optional_cmd = @typeInfo(CmdMaybeUnion) == .Optional;

            const maybe_cmd_field_value = @field(args, sub_cmd_s_field_name);
            const cmd_field_value = if (is_optional_cmd)
                maybe_cmd_field_value orelse return
            else
                maybe_cmd_field_value;

            switch (cmd_field_value) {
                inline else => |payload, itag| {
                    const sub_cmd_name = @tagName(itag);
                    const sub_cmd_info = @field(sub_cmd_info_map, sub_cmd_name);
                    const sub_parent = parent_prefix ++
                        sub_cmd_s_field_name ++ "." ++ @tagName(itag);
                    const sub_helper = CmdHelper(@TypeOf(payload), sub_cmd_info, sub_parent);
                    sub_helper.freeImpl(allocator, payload);
                },
            }
        }

        fn freeOptions(allocator: std.mem.Allocator, partial_args: Cmd) void {
            @setEvalBranchQuota(opt_enum_to_field_map.len * 8 + 1);
            inline for (opt_enum_to_field_map) |s_field_idx| {
                const s_field = cmd_fields[s_field_idx.index];
                const maybe_target_field = @field(partial_args, s_field.name);
                const target_field = blk: {
                    const s_sub_field_idx = s_field_idx.sub orelse break :blk maybe_target_field;
                    const s_sub_fields = @typeInfo(s_field.type).Struct.fields;
                    const s_sub_field = s_sub_fields[s_sub_field_idx];
                    break :blk @field(maybe_target_field, s_sub_field.name);
                };
                const ptr_info = switch (@typeInfo(@TypeOf(target_field))) {
                    .Pointer => |ptr_info| ptr_info,
                    else => continue,
                };
                if (ptr_info.size != .Slice) continue;
                if (ptr_info.child == u8) continue;
                allocator.free(target_field);
            }
        }

        fn parseInner(
            allocator: std.mem.Allocator,
            /// `*const [n][]const u8`
            command_chain: anytype,
            tty_config: std.io.tty.Config,
            /// `std.io.GenericWriter(...)` | `std.io.AnyWriter`
            help_writer: anytype,
            args_iter: *ArgsIter,
        ) (ParseCmdError || @TypeOf(help_writer).Error)!?Cmd {
            var result: Cmd = default_init;
            errdefer freeOptions(allocator, result);

            const parse_result: union(enum) {
                help,
                subcmd_set: if (maybe_sub_cmd_s_field_index != null) void else noreturn,
                subcmd_unset,
            } = while (args_iter.next()) |arg| {
                if (arg.len == 0) continue;

                parse_opt: {
                    const key, //
                    const maybe_value //
                    = try parseOptionKeyMaybeValStr(arg) orelse break :parse_opt;

                    const is_help = switch (key) {
                        .short => |alias| alias == 'h',
                        .long => |name| constEql(name, "help"),
                    };

                    if (is_help and maybe_value != null) {
                        return error.UnexpectedValueForFlag;
                    }

                    if (is_help) {
                        try writeHelp(command_chain, tty_config, help_writer);
                        break .help;
                    }

                    const opt_tag: OptEnum = switch (key) {
                        .short => |alias| optionTagFromAlias(alias) orelse
                            return error.UnrecognizedOptionAlias,
                        .long => |name| optionTagFromName(name) orelse
                            return error.UnrecognizedOptionName,
                    };

                    switch (opt_tag) {
                        inline else => |itag| {
                            const s_field_idx = opt_enum_to_field_map[@intFromEnum(itag)];
                            const s_field = cmd_fields[s_field_idx.index];
                            const s_field_ptr = &@field(result, s_field.name);
                            const maybe_opt_info = @field(cmd_info.sub, s_field.name);

                            const opt_name, const opt_ptr, const opt_info = opt: {
                                const s_sub_field_idx = s_field_idx.sub orelse break :opt .{
                                    s_field.name,
                                    s_field_ptr,
                                    maybe_opt_info,
                                };
                                const s_sub_fields = @typeInfo(s_field.type).Struct.fields;
                                const s_sub_field = s_sub_fields[s_sub_field_idx];
                                const s_sub_field_ptr = &@field(s_field_ptr, s_sub_field.name);
                                break :opt .{
                                    s_sub_field.name,
                                    s_sub_field_ptr,
                                    @field(maybe_opt_info, s_sub_field.name),
                                };
                            };

                            const Opt = @TypeOf(opt_ptr.*);
                            const is_list, const ValueType = switch (@typeInfo(Opt)) {
                                .Pointer => |ptr_info| blk: {
                                    const is_list = ptr_info.size == .Slice and
                                        (ptr_info.child != u8 or opt_info.config == .list);
                                    const ListElem = if (is_list) ptr_info.child else Opt;
                                    break :blk .{ is_list, ListElem };
                                },
                                else => .{ false, Opt },
                            };
                            const parsed_value = try parseSingleOptValueMaybeScan(
                                opt_name,
                                ValueType,
                                maybe_value,
                                args_iter,
                            );
                            if (!is_list) {
                                opt_ptr.* = parsed_value;
                            } else {
                                opt_ptr.* = try allocator.realloc(
                                    @constCast(opt_ptr.*),
                                    opt_ptr.len + 1,
                                );
                                @constCast(&opt_ptr.*[opt_ptr.len - 1]).* = parsed_value;
                            }
                        },
                    }

                    continue;
                }

                const sub_cmd_s_field_index = maybe_sub_cmd_s_field_index orelse {
                    return error.UnexpectedPositional;
                };
                const sub_cmd_s_field_info = cmd_fields[sub_cmd_s_field_index];
                const sub_cmd_s_field_name = sub_cmd_s_field_info.name;
                const CmdMaybeUnion = sub_cmd_s_field_info.type;

                const sub_cmd_info_map = @field(cmd_info.sub, sub_cmd_s_field_name);
                const CmdUnion, const is_optional_cmd = switch (@typeInfo(CmdMaybeUnion)) {
                    .Union => .{ CmdMaybeUnion, false },
                    .Optional => |o_info| .{ o_info.child, true },
                    else => unreachable,
                };

                const CmdEnum = @typeInfo(CmdUnion).Union.tag_type.?;
                const cmd_tag = enumFromStringAfterReplacingScalarInTag(
                    arg,
                    CmdEnum,
                    '_',
                    '-',
                ) orelse return error.UnrecognizedCommand;

                const maybe_cmd_field_ptr = &@field(result, sub_cmd_s_field_name);
                const cmd_field_ptr = if (!is_optional_cmd) maybe_cmd_field_ptr else blk: {
                    maybe_cmd_field_ptr.* = @as(CmdUnion, undefined);
                    break :blk &maybe_cmd_field_ptr.*.?;
                };
                switch (cmd_tag) {
                    inline else => |itag| {
                        const sub_cmd_name = @tagName(itag);
                        const sub_cmd_info = @field(sub_cmd_info_map, sub_cmd_name);
                        cmd_field_ptr.* = @unionInit(CmdUnion, sub_cmd_name, undefined);
                        const subcmd_ptr = &@field(cmd_field_ptr, sub_cmd_name);
                        const SubCmd = @TypeOf(subcmd_ptr.*);

                        const sub_parent =
                            parent_prefix ++ sub_cmd_s_field_name ++ "." ++ sub_cmd_name;
                        const sub_helper = CmdHelper(SubCmd, sub_cmd_info, sub_parent);
                        subcmd_ptr.* = try sub_helper.parseInner(
                            allocator,
                            command_chain ++ .{arg},
                            tty_config,
                            help_writer,
                            args_iter,
                        ) orelse break .help;
                        break .subcmd_set;
                    },
                }
            } else .subcmd_unset;
            std.debug.assert(args_iter.peek() == null or parse_result == .help);

            switch (parse_result) {
                .help => {
                    freeOptions(allocator, result);
                    return null;
                },
                .subcmd_set => comptime std.debug.assert(maybe_sub_cmd_s_field_index != null),
                .subcmd_unset => if (maybe_sub_cmd_s_field_index) |sub_cmd_s_field_index| {
                    const sub_cmd_s_field_info = cmd_fields[sub_cmd_s_field_index];
                    const sub_cmd_s_field_name = sub_cmd_s_field_info.name;
                    const CmdMaybeUnion = sub_cmd_s_field_info.type;

                    if (@typeInfo(CmdMaybeUnion) != .Optional) return error.MissingCommand;
                    @field(result, sub_cmd_s_field_name) = null;
                },
            }

            return result;
        }

        fn writeHelp(
            /// `*const [n][]const u8`
            command_chain: anytype,
            tty_config: std.io.tty.Config,
            /// `std.io.GenericWriter(...)` | `std.io.AnyWriter`
            writer: anytype,
        ) (@TypeOf(writer).Error || std.os.windows.SetConsoleTextAttributeError)!void {
            try tty_config.setColor(writer, .yellow);
            try writer.writeAll("USAGE:\n");
            try writer.writeByteNTimes(' ', 2);

            try tty_config.setColor(writer, .green);
            try writer.writeAll(command_chain[0]);
            try writer.writeByte(' ');
            for (command_chain[1..]) |subcmd_str| {
                try writer.writeAll(subcmd_str);
                try writer.writeByte(' ');
            }
            try writer.writeAll("[OPTIONS]");

            try tty_config.setColor(writer, .reset);
            try writer.writeByteNTimes('\n', 2);
            try writer.writeAll(cmd_info.help.short);

            if (cmd_info.help.long) |long_help| {
                try writer.writeByteNTimes('\n', 2);
                try writer.writeAll(long_help);
            }

            try writer.writeByte('\n');

            if (maybe_subcmd_list) |subcmd_list| {
                try writer.writeByte('\n');

                try tty_config.setColor(writer, .yellow);
                try writer.writeAll("COMMANDS:");

                const name_base_width = min: {
                    var largest_width: u64 = 0;
                    for (subcmd_list) |name_help_pair| {
                        const subcmd_name, _ = name_help_pair;
                        largest_width = @max(largest_width, subcmd_name.len);
                    }
                    break :min largest_width;
                };

                for (subcmd_list) |name_help_pair| {
                    const subcmd_name, const subcmd_short_help = name_help_pair;

                    try tty_config.setColor(writer, .green);
                    try writer.writeByte('\n');
                    try writer.writeByteNTimes(' ', 2);

                    try writer.writeAll(subcmd_name);
                    const padding = name_base_width - subcmd_name.len + 3;
                    try tty_config.setColor(writer, .reset);
                    try writer.writeByteNTimes(' ', padding);

                    const indent = 2 + name_base_width + 3;
                    try writeIndentedText(writer, indent, subcmd_short_help);
                }

                try writer.writeByte('\n');
            }

            try writer.writeByte('\n');

            try tty_config.setColor(writer, .yellow);
            try writer.writeAll("OPTIONS:");

            const help_option_alias_name = "-h, --help";

            const name_alias_base_width: u64, //
            const default_value_base_width: ?u64 //
            = min: {
                var max_name_alias_width: u64 = help_option_alias_name.len;
                var max_default_value_width: ?u64 = null;

                @setEvalBranchQuota(opt_enum_to_field_map.len * 8 + 1);
                inline for (opt_enum_to_field_map, 0..opt_enum_fields.len) |s_field_idx, e_int| {
                    const opt_tag: OptEnum = @enumFromInt(e_int);
                    const s_field = cmd_fields[s_field_idx.index];
                    const maybe_opt_info = @field(cmd_info.sub, s_field.name);
                    const opt_info = if (s_field_idx.sub) |s_sub_field_idx| blk: {
                        const s_sub_fields = @typeInfo(s_field.type).Struct.fields;
                        const s_sub_field = s_sub_fields[s_sub_field_idx];
                        break :blk @field(maybe_opt_info, s_sub_field.name);
                    } else @as(OptionInfo(s_field.type), maybe_opt_info);

                    var cw = std.io.countingWriter(std.io.null_writer);
                    writeOptionNameWithDefault(
                        opt_info.alias,
                        @tagName(opt_tag),
                        cw.writer(),
                    ) catch |err| switch (err) {};
                    max_name_alias_width = @max(
                        max_name_alias_width,
                        cw.bytes_written,
                    );

                    cw.bytes_written = 0;
                    if (renderOptionDefaultValue(
                        opt_info.default_value,
                        cw.writer(),
                    ) catch |err| switch (err) {}) {
                        max_default_value_width = @max(
                            max_default_value_width orelse 0,
                            cw.bytes_written,
                        );
                    }
                }
                break :min .{ max_name_alias_width, max_default_value_width };
            };

            @setEvalBranchQuota(opt_enum_to_field_map.len * 8 + 1);
            inline for (opt_enum_to_field_map, 0..opt_enum_fields.len) |s_field_idx, e_int| {
                const opt_kebab_tag: OptEnum = @enumFromInt(e_int);
                const s_field = cmd_fields[s_field_idx.index];
                const maybe_opt_info = @field(cmd_info.sub, s_field.name);
                const opt_info = if (s_field_idx.sub) |s_sub_field_idx| blk: {
                    const s_sub_fields = @typeInfo(s_field.type).Struct.fields;
                    const s_sub_field = s_sub_fields[s_sub_field_idx];
                    break :blk @field(maybe_opt_info, s_sub_field.name);
                } else @as(OptionInfo(s_field.type), maybe_opt_info);

                const multiline_help = std.mem.indexOfScalar(u8, opt_info.help, '\n') != null;

                // write indent and separating newlines
                try tty_config.setColor(writer, .green);
                if (multiline_help) try writer.writeByte('\n');
                try writer.writeByte('\n');
                try writer.writeByteNTimes(' ', 2);

                // write option alias & name
                var cw = std.io.countingWriter(writer);
                try writeOptionNameWithDefault(
                    opt_info.alias,
                    @tagName(opt_kebab_tag),
                    cw.writer(),
                );

                // write padding
                try tty_config.setColor(writer, .reset);
                try writer.writeByteNTimes(' ', name_alias_base_width - cw.bytes_written + 2);

                // maybe write default value
                cw.bytes_written = 0;
                _ = try renderOptionDefaultValue(
                    opt_info.default_value,
                    cw.writer(),
                );

                // write padding
                try writer.writeByteNTimes(' ', 1 + padding: {
                    const base_width = default_value_base_width orelse break :padding 0;
                    break :padding base_width - cw.bytes_written + 2;
                });

                // write help description and newline
                const indent = 2 + name_alias_base_width + 2 +
                    if (default_value_base_width) |base_width| (base_width + 3) else 1;
                try writeIndentedText(writer, indent, opt_info.help);
                if (multiline_help) try writer.writeByte('\n');
            }

            try tty_config.setColor(writer, .green);
            try writer.writeByte('\n');
            try writer.writeByteNTimes(' ', 2);

            try writer.writeAll(help_option_alias_name);
            const padding1 =
                name_alias_base_width -
                help_option_alias_name.len + 3 -
                @intFromBool(default_value_base_width != null);
            const padding2 = if (default_value_base_width) |base_width| base_width + 3 else 0;

            try tty_config.setColor(writer, .reset);
            try writer.writeByteNTimes(' ', padding1 + padding2);

            try writer.writeAll("Prints help information\n");
        }

        inline fn optionTagFromAlias(alias: u8) ?OptEnum {
            if (alias_table.len == 0) return null;

            if (alias < ALIAS_TABLE_IDX_BASE) return null;
            if (alias - ALIAS_TABLE_IDX_BASE >= alias_table.len) return null;

            const value = alias_table[alias - ALIAS_TABLE_IDX_BASE];
            if (alias_table_has_holes and value == alias_table_sentinel) return null;
            return @enumFromInt(value);
        }

        inline fn optionTagFromName(name: []const u8) ?OptEnum {
            if (opt_enum_fields.len == 0) return null;
            return enumFromStringAfterReplacingScalarInTag(name, OptEnum, '_', '-');
        }
    };
}

/// compute information about this option field, using information
/// only known after `computeCmdAndOptBasicInfo(Cmd)`.
fn computeOptFieldInfo(
    comptime maybe_parent_name: ?[]const u8,

    //
    comptime field_name: []const u8,
    comptime FieldType: type,
    comptime opt_info: OptionInfo(FieldType),

    //
    comptime opt_enum_fields: *[]const std.builtin.Type.EnumField,

    //
    comptime default_init_ptr: anytype,

    //
    comptime OptEnumIntMax: type,
    comptime alias_table_wip: *[MAX_ALIAS_TABLE_LEN]OptEnumIntMax,
) void {
    const parent_name = maybe_parent_name orelse "root";
    const parent_prefix = parent_name ++ ".";

    const opt_enum_field_name = (opt_info.name_override orelse field_name) ++ "";
    if (constEql(opt_enum_field_name, "help")) @compileError(
        "Cannot use reserved option name " ++ parent_prefix ++ "help",
    );

    const opt_enum_field_idx = opt_enum_fields.len;
    opt_enum_fields.* = opt_enum_fields.* ++ .{.{
        .name = opt_enum_field_name,
        .value = opt_enum_field_idx,
    }};

    if (opt_info.alias != .none) {
        const idx = @intFromEnum(opt_info.alias) - ALIAS_TABLE_IDX_BASE;
        alias_table_wip[idx] = opt_enum_field_idx;
    }

    const is_slice = switch (@typeInfo(FieldType)) {
        .Pointer => |ptr_info| switch (ptr_info.size) {
            .Slice => ptr_info.child != u8 or opt_info.config == .list,
            else => false,
        },
        else => false,
    };

    if (is_slice) {
        // default init lists to empty.
        @field(default_init_ptr, field_name) = &.{};
    }

    const default_value = opt_info.default_value;
    @field(default_init_ptr, field_name) = default_value;

    if (is_slice and default_value.len != 0 and
        @TypeOf(default_value[0]) != u8) @compileError(
        "Don't default initialize slice field with a buffer: " ++
            parent_prefix ++ field_name,
    );
}

/// compute the sub-info struct and some basic facts about the option fields
/// that don't require the sub-info to be defined.
fn computeCmdAndOptBasicInfo(
    comptime T: type,
    comptime maybe_parent_name: ?[]const u8,
) struct {
    SubInfo: type,
    option_count: usize,
    maybe_sub_cmd_s_field_index: ?usize,
} {
    const parent_name = maybe_parent_name orelse "root";

    const s_info = switch (@typeInfo(T)) {
        .Struct => |s_info| s_info,
        .Void => @typeInfo(struct {}).Struct,
        else => unreachable,
    };

    var opt_count: usize = 0;
    var fields: [s_info.fields.len]std.builtin.Type.StructField = undefined;
    var maybe_sub_cmd_s_field_index: ?usize = null;

    @setEvalBranchQuota(s_info.fields.len * 2 + 1);
    for (&fields, s_info.fields, 0..) |*new_s_field, s_field, s_field_i| {
        const UnwrappedStructFieldType = switch (@typeInfo(s_field.type)) {
            .Optional => |o_info| switch (@typeInfo(o_info.child)) {
                .Union => o_info.child,
                else => s_field.type,
            },
            else => s_field.type,
        };

        const FieldType = switch (@typeInfo(UnwrappedStructFieldType)) {
            .Union => |sub_u_info| sub_infos: {
                if (maybe_sub_cmd_s_field_index) |prev| @compileError(
                    "Cannot have two sub-command union fields in " ++ parent_name ++ ": " ++
                        s_info.fields[prev].name ++ " & " ++ s_field.name,
                );

                maybe_sub_cmd_s_field_index = s_field_i;

                @setEvalBranchQuota(
                    s_info.fields.len * 2 + 1 +
                        sub_u_info.fields.len * 2 + 1,
                );
                break :sub_infos UnionOptDescSubMap(UnwrappedStructFieldType);
            },
            .Struct => |s_sub_info| sub_map: {
                opt_count += s_sub_info.fields.len;
                @setEvalBranchQuota(
                    s_info.fields.len * 2 + 1 +
                        s_sub_info.fields.len * 2 + 1,
                );
                break :sub_map OptionInfoGroup(UnwrappedStructFieldType);
            },
            else => opt_info: {
                opt_count += 1;
                break :opt_info OptionInfo(UnwrappedStructFieldType);
            },
        };

        new_s_field.* = .{
            .name = s_field.name,
            .type = FieldType,
            .default_value = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    const SubInfo = @Type(.{ .Struct = .{
        .layout = .auto,
        .backing_integer = null,
        .fields = &fields,
        .is_tuple = false,
        .decls = &.{},
    } });
    return .{
        .SubInfo = SubInfo,
        .option_count = opt_count,
        .maybe_sub_cmd_s_field_index = maybe_sub_cmd_s_field_index,
    };
}

fn UnionOptDescSubMap(comptime U: type) type {
    const sub_u_info = @typeInfo(U).Union;
    var new_s_fields: [sub_u_info.fields.len]std.builtin.Type.StructField = undefined;

    for (&new_s_fields, sub_u_info.fields) |*new_s_field, u_field| {
        new_s_field.* = .{
            .name = u_field.name,
            .type = CommandInfo(u_field.type),
            .default_value = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{ .Struct = .{
        .layout = .auto,
        .backing_integer = null,
        .fields = &new_s_fields,
        .is_tuple = false,
        .decls = &.{},
    } });
}

const ArgsIter = struct {
    args: []const []const u8,
    index: usize,

    fn peek(self: *const ArgsIter) ?[]const u8 {
        if (self.index == self.args.len) return null;
        return self.args[self.index];
    }

    fn next(self: *ArgsIter) ?[]const u8 {
        const result = self.peek() orelse return null;
        self.index += 1;
        return result;
    }
};

const OptionKeyNameOrAlias = union(enum) {
    short: u8,
    long: []const u8,
};

const ParseOptionKeyMaybeValStrError = error{
    UnexpectedSingleDash,
    AliasMissingEql,
    MissingValueAfterEqual,
    UnexpectedDoubleDash,
};

/// Parses `-{c}`, `--{name}`, optionally followed by `={value}`.
/// Returns null if `arg[0] != '-'`.
fn parseOptionKeyMaybeValStr(
    arg: []const u8,
) ParseOptionKeyMaybeValStrError!?struct {
    OptionKeyNameOrAlias,
    ?[]const u8,
} {
    if (arg[0] != '-') return null;
    if (arg.len == 1) return error.UnexpectedSingleDash;

    if (arg[1] != '-') { // '-{c}'
        const key: OptionKeyNameOrAlias = .{ .short = arg[1] };
        if (arg.len == 2) return .{ key, null };
        if (arg[2] != '=') return error.AliasMissingEql;
        if (arg.len == 3) return error.MissingValueAfterEqual;
        return .{ key, arg[3..] };
    }

    if (arg.len == 2) return error.UnexpectedDoubleDash;

    const maybe_eql_idx = std.mem.indexOfScalarPos(u8, arg, 2, '=');
    const opt_name_str = arg[2 .. maybe_eql_idx orelse arg.len];
    const key: OptionKeyNameOrAlias = .{ .long = opt_name_str };

    const maybe_val = if (maybe_eql_idx) |eql_idx| arg[eql_idx + 1 ..] else null;
    if (maybe_val) |val| if (val.len == 0) return error.MissingValueAfterEqual;
    return .{ key, maybe_val };
}

const ParseOptValueError =
    ParseSingleOptValueError ||
    std.mem.Allocator.Error;

fn parseSingleOptValueMaybeScan(
    comptime option_name: []const u8,
    comptime T: type,
    maybe_value: ?[]const u8,
    args_iter: *ArgsIter,
) ParseSingleOptValueError!T {
    return parseSingleOptValue(option_name, T, maybe_value) catch |err| switch (err) {
        error.MissingValue => parseSingleOptValue(option_name, T, args_iter.next()),
        else => |e| return e,
    };
}

const ParseSingleOptValueError = error{
    UnexpectedValueForFlag,
    MissingValue,
    InvalidValue,
};

fn parseSingleOptValue(
    comptime option_name: []const u8,
    comptime T: type,
    maybe_value: ?[]const u8,
) ParseSingleOptValueError!T {
    if (T == []const u8) {
        return maybe_value orelse return error.MissingValue;
    }

    switch (@typeInfo(T)) {
        .Bool => {
            const value_str = maybe_value orelse return true;
            if (std.mem.eql(u8, value_str, "true")) return true;
            if (std.mem.eql(u8, value_str, "false")) return false;
            return error.InvalidValue;
        },
        .Int => {
            const value_str = maybe_value orelse return {
                return error.MissingValue;
            };
            return std.fmt.parseInt(T, value_str, 0) catch {
                return error.InvalidValue;
            };
        },
        .Enum => {
            const value_str = maybe_value orelse return {
                return error.MissingValue;
            };
            return std.meta.stringToEnum(T, value_str) orelse {
                return error.InvalidValue;
            };
        },
        .Optional => |optional| if (@typeInfo(optional.child) != .Optional) {
            return try parseSingleOptValue(option_name, optional.child, maybe_value);
        },
        else => {},
    }

    @compileError("Unexpected option type: " ++ option_name ++ ": " ++ @typeName(T));
}

/// Writes `"-?, --{name}"`, or `"    --{name}"`.
/// Replaces all '_' in `name` with '-'.
fn writeOptionNameWithDefault(
    opt_alias: OptionAlias,
    opt_name: []const u8,
    /// `std.io.GenericWriter(...)` | `std.io.AnyWriter`
    writer: anytype,
) @TypeOf(writer).Error!void {
    if (opt_alias != .none) {
        try writer.print("-{c}, ", .{@intFromEnum(opt_alias)});
    } else {
        try writer.writeByteNTimes(' ', 4);
    }
    try writer.writeAll("--");
    var start_idx: usize = 0;
    while (std.mem.indexOfScalarPos(u8, opt_name, start_idx, '_')) |end_idx| {
        defer start_idx = end_idx + 1;
        try writer.writeAll(opt_name[start_idx..end_idx]);
        try writer.writeByte('-');
    }
    try writer.writeAll(opt_name[start_idx..]);
}

/// Returns true only if the value was rendered.
inline fn renderOptionDefaultValue(
    comptime default_value: anytype,
    /// `std.io.GenericWriter(...)` | `std.io.AnyWriter`
    writer: anytype,
) !bool {
    const T = @TypeOf(default_value);
    const value, const fmt_str = if (T == []const u8)
        .{ std.zig.fmtEscapes(default_value), "" }
    else switch (@typeInfo(T)) {
        .Bool => .{ default_value, "any" },
        .Enum => .{ @tagName(default_value), "s" },
        .Int => .{ default_value, "d" },
        .Optional => |optional| {
            if (@typeInfo(optional.child) == .Optional) return false;
            return renderOptionDefaultValue(default_value orelse return false, writer);
        },
        else => return false,
    };
    try writer.writeAll("(default: ");
    try std.fmt.formatType(value, fmt_str, .{}, writer, 8);
    try writer.writeAll(")");
    return true;
}

fn writeIndentedText(
    /// `std.io.GenericWriter(...)` | `std.io.AnyWriter`
    writer: anytype,
    indent: u64,
    text: []const u8,
) @TypeOf(writer).Error!void {
    const first_line_end = std.mem.indexOfScalar(u8, text, '\n') orelse {
        try writer.writeAll(text);
        return;
    };

    try writer.writeAll(text[0..first_line_end]);
    var spliterator = std.mem.splitScalar(u8, text[first_line_end + 1 ..], '\n');
    while (spliterator.next()) |line| {
        try writer.writeByte('\n');
        try writer.writeByteNTimes(' ', indent);
        try writer.writeAll(line);
    }
}

fn enumFromStringAfterReplacingScalarInTag(
    str: []const u8,
    comptime E: type,
    comptime target: u8,
    comptime replacement: u8,
) ?E {
    const e_info = @typeInfo(E).Enum;
    @setEvalBranchQuota(e_info.fields.len * 3 + 2);
    inline for (e_info.fields) |e_field| {
        const replaced_tag = comptime comptimeReplaceScalar(e_field.name, target, replacement);
        if (constEql(replaced_tag, str)) return @enumFromInt(e_field.value);
    }
    return null;
}

inline fn comptimeReplaceScalar(
    comptime input: []const u8,
    comptime target: u8,
    comptime replacement: u8,
) []const u8 {
    comptime {
        const StrVec = @Vector(input.len, u8);
        const target_splat: StrVec = @splat(target);
        const replacement_splat: StrVec = @splat(replacement);

        var result_vec: StrVec = input[0..].*;
        result_vec = @select(u8, result_vec == target_splat, replacement_splat, result_vec);
        const result: [input.len]u8 = result_vec;
        return &result;
    }
}

/// Compares `a` and `b` as strings, assuming one or both of them is/are of constant length.
inline fn constEql(a: []const u8, b: []const u8) bool {
    const a_is_const = @typeInfo(@TypeOf(.{a.len})).Struct.fields[0].is_comptime;
    const b_is_const = @typeInfo(@TypeOf(.{b.len})).Struct.fields[0].is_comptime;
    if (!a_is_const and !b_is_const) @compileError("Neither a nor b is of constant length");

    if (a.len != b.len) return false;
    const len = if (a_is_const) a.len else if (b_is_const) b.len else unreachable;

    const a_vec: @Vector(len, u8) = a[0..len].*;
    const b_vec: @Vector(len, u8) = b[0..len].*;
    return @reduce(.And, a_vec == b_vec);
}
