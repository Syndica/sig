//! # Commands
//! This library is built for parsing subcommand-based argument structures.
//! Tha means there is an implicit parent command (ie the executable itself),
//! which has zero or more subcommands, each of which itself may have zero or
//! more subcommands themselves, recusively. If a (sub)command does not have
//! any subcommands, it may accept positional arguments.
//!
//! For example, the command `foo --fizz="1" bar --buzz baz --fizzbuzz` can be broken
//! down like so:
//! ```zig
//! .foo = .{
//!     .fizz = "1",
//!     .subcmd = .{ .bar = .{
//!         .buzz = true,
//!         .subcmd = .{ .baz = .{
//!             .fizzbuzz = true,
//!         } },
//!     } },
//! }
//! ```
//!
//! # Arguments
//! A given command may accept zero or more arguments, named arguments that may
//! also be specified via an alias that is unique to it (per subcommand).
//! An argument may be of type bool, int, string, enum, and an optional xor
//! list of any of the former primitives.
//!
//! Note: the `-h, --help` argument cannot be used by the programmer, it is
//! controlled by the parser.
//!
//! ## Optional Arguments, Required Arguments, Default Values
//! The library has no concept of a "required" argument in and of itself, because
//! all arguments must have a default value.
//!
//! An application may itself make an argument "required" by using an optional
//! type with a default value of `null`, and issue an error if the argument posseses
//! this value, because `null` is not a valid/specifiable value for an optional on the
//! command line, meaning if the value is `null`, the application can know for certain
//! that the argument was not specified at all.
//!
//! ## List Arguments
//! List arguments are inherently "optional", in the sense that they are not allowed
//! to have a non-empty default value, and will always default to an empty value
//! if no values are specified. For this reason, a list cannot be optional, because
//! whether or not the argument was specified can be detected by whether or not the
//! list is empty.
//!
//! Syntactically, lists are specified as a repeating series of the argument.
//! Example: `foo --bar 1 --bar 2 --bar 3 --bar 4`, would parse to a command
//! where the argument `bar` is equal to `&.{ 1, 2, 3, 4 }`.
//!
//! ## Positional Arguments
//! A positional argument is only allowed if there is no subcommand, and vice versa.
//! They are specified before named arguments, and not after; for example:
//! `foo file/path --arg=a`, but not `foo --arg=a file/path`.

const std = @import("std");
const std14 = @import("std14");

// -- API -- //

/// This is the core tool you will use to describe the shape of the command line parser.
///
/// The input `S` must be a struct type where each field is one of the following:
/// * A union where each tag represents a subcommand.
/// * A struct where each field is an argument.
/// * A simple value which is assigned to an argument.
///
/// Up to one union field is allowed, because at most one subcommand field is permitted,
/// which is what a union represents (each tag of the union is a subcommand name).
///
/// The `sub: SubInfo` field is a struct with all of the same fields as the input struct `S`,
/// except:
/// * each union field type is replaced with `CommandInfo(FieldType)`.
/// * each struct field type is replaced with `ArgumentInfoGroup(FieldType)`.
/// * each normal field type is replaced with `ArgumentInfo(FieldType)`.
///
/// NOTE: each subcommand field must be optional, such that its absence in the command line
/// can be represented as `null`, allowing the calling code to take appropriate action for
/// any missing subcommand.
///
/// This can be specified directly at the usage site, but is conventionally declared as a
/// constant in the namespace of the struct type, ie:
/// ```zig
/// const cmd_info: cli.CommandInfo(@This()) = .{
///     .help = .{
///         .short = "A brief but helpful description.",
///         .long = "A much longer description, potentially on multiple lines, or null.",
///     },
///     .sub = .{
///         // -- snip --
///     },
/// };
/// ```
/// This can then be passed `Parser` as `Parser(Cmd, Cmd.cmd_info)`.
pub fn CommandInfo(comptime S: type) type {
    return struct {
        help: CommandHelp,
        sub: SubInfo,

        pub const Cmd = S;
        pub const SubInfo = computeCmdAndArgBasicInfo(S, null).SubInfo;
    };
}

pub const CommandHelp = struct {
    /// Brief description of the command to be displayed as part of the parent command's help message,
    /// recommended but not required to be one line.
    ///
    /// Also displayed as part of the target command's help message, just before the long description.
    short: []const u8,
    /// Long description of the command to be displayed as part of the target command's help message,
    /// optionally applicable if a more verbose description is helpful or required.
    ///
    /// It is recommended that this be worded in a way which is not redundant with the brief, since it
    /// will be displayed as a paragraph that follows the brief.
    long: ?[]const u8,
};

/// This struct describes everything related to a given argument within the scope of a (sub)command.
///
/// Similar to `CommandInfo`, it can be instantiated directly at the site of usage, or it can
/// be pre-declared, which allows re-using the argument info in multiple sub-commands.
pub fn ArgumentInfo(comptime Arg: type) type {
    return struct {
        /// A named argument will be specifiable as `--{name_override orelse field_name}(=<value>)?`,
        /// irrespective of position within the scope of the (sub)command.
        ///
        /// A positional argument will be specifiable as `{<value>}`, with respect to the position
        /// it is declared relative to other positional arguments within the scope of the (sub)command.
        kind: enum { named, positional },

        /// Used to override the name displayed on the command line, or null
        /// to simply use the associated field name; snake case strings are
        /// transformed into kebab case strings, both for specification on the
        /// command line, and for display on the help message.
        /// For positionals, this is not specifiable on the command line, but
        /// is used in the help message.
        name_override: ?[]const u8,

        /// The alias associated with this argument, or `.none`.
        alias: ArgumentAlias,

        /// Default value to use for this argument.
        default_value: Argument,

        /// Options describing how the value(s) should be parsed.
        /// For `Arg = []const T` & `Arg = ?T`, applies to `T`,
        /// except for `T = []const u8`, which would always be
        /// interpeted as a string.
        config: Config,

        /// The help information associated with this argument.
        help: []const u8,

        pub const Argument = Arg;
        pub const Config = ArgumentConfig(Argument);

        comptime {
            if (!isArgumentInfo(@This())) @compileError(
                "isArgumentInfo has gone out of sync with " ++ @typeName(@This()),
            );
        }
    };
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

/// Exhaustive enum representing a single alphabetic character,
/// aside from the letter 'h' (`[A-Za-gi-z]`).
pub const ArgumentAlias = enum(u7) {
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

    // NOTE: 'h' excluded as the reserved help flag.
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
};

/// Returns a struct with all the same fields as input struct `S`, but where each
/// field is of type `ArgumentInfo(FieldType)`.
///
/// Certain groups of arguments may appear together repeatedly across subcommands;
/// for this reason, struct fields in the struct passed to `CommandInfo` are described
/// using this type, allowing re-use of those struct types across subcommands.
///
/// Each of the argument infos in the struct are embedded into the parent pool of
/// arguments; an error is issued if any name or alias collisions occur.
pub fn ArgumentInfoGroup(comptime S: type) type {
    const Type = std.builtin.Type;
    const s_info = @typeInfo(S).@"struct";

    var sub_fields: [s_info.fields.len]Type.StructField = undefined;
    for (&sub_fields, s_info.fields) |*new_s_field, s_field| {
        if (@typeInfo(s_field.type) == .@"union" or
            (@typeInfo(s_field.type) == .optional and
                @typeInfo(@typeInfo(s_field.type).optional.child) == .@"union"))
        {
            @compileError("The subcommand field cannot be part of an argument group");
        }

        new_s_field.* = .{
            .name = s_field.name,
            .type = ArgumentInfo(s_field.type),
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{ .@"struct" = .{
        .layout = .auto,
        .backing_integer = null,
        .fields = &sub_fields,
        .is_tuple = false,
        .decls = &.{},
    } });
}

pub const ParseCmdError = error{
    /// Unrecognized `--{name}`.
    UnrecognizedArgumentName,
    /// Unrecognized `-{c}`.
    UnrecognizedArgumentAlias,
    /// Unexpected positional in command with no subcommand and not expecting positionals.
    UnexpectedPositional,
    /// Unrecognized command string.
    UnrecognizedCommand,
} || ParseArgumentKeyMaybeValStrError ||
    ParseSingleArgValueError ||
    WriteHelpError ||
    std.mem.Allocator.Error;

pub const WriteHelpError = error{
    /// The help writer returned an error.
    HelpWriteFail,
    /// The tty config returned an error.
    TtyFail,
};

pub fn Parser(
    /// Must be a struct type containing zero or more argument fields, and optionally
    /// one sub-command field which is an optional tagged union, wherein each
    /// member is a sub-command struct following the same description as this one,
    /// recursively.
    /// See `CommandInfo`.
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
        ) ParseCmdError!?Cmd {
            var args_iter: ArgsIter = .{ .args = args, .index = 0 };
            return helper.parseInner(
                allocator,
                &[_][]const u8{program_name},
                tty_config,
                .{ .context = help_writer.any() },
                &args_iter,
            );
        }

        pub fn free(allocator: std.mem.Allocator, cmd: Cmd) void {
            helper.freeImpl(allocator, cmd);
        }
    };
}

// -- UNIT TESTING -- //

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
        subcmd: ?union(enum) {
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
                    .kind = .named,
                    .name_override = null,
                    .alias = .l,
                    .default_value = .debug,
                    .config = {},
                    .help = "The amount of detail to log",
                },
                .metrics_port = .{
                    .kind = .named,
                    .name_override = null,
                    .alias = .m,
                    .default_value = 12345,
                    .config = {},
                    .help = "The metrics port",
                },
            },
        };

        // structs can be used to share arguments across commands
        const Shared = struct {
            fizz: u32,
            buzz: []const u64,

            const arg_info: ArgumentInfoGroup(@This()) = .{
                .fizz = .{
                    .kind = .named,
                    .name_override = null,
                    .alias = .f,
                    .default_value = 32,
                    .config = {},
                    .help = "fizzy",
                },
                .buzz = .{
                    .kind = .named,
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
                    .shared = Shared.arg_info,
                },
            };
        };

        const Gossip = struct {
            file_path: ?[]const u8 = null,
            gossip_port: u16,
            entrypoints: []const []const u8,
            shared: Shared,

            const cmd_info: CommandInfo(@This()) = .{
                .help = .{
                    .short = "Run gossip",
                    .long = "Sub-Test CLI",
                },
                .sub = .{
                    .file_path = .{
                        .kind = .positional,
                        .name_override = "file",
                        .alias = .none,
                        .default_value = null,
                        .config = .string,
                        .help = "Input file",
                    },
                    .shared = Shared.arg_info,
                    .gossip_port = .{
                        .kind = .named,
                        .name_override = null,
                        .alias = .p,
                        .default_value = 8020,
                        .config = {},
                        .help = "The port to run gossip listener",
                    },
                    .entrypoints = .{
                        .kind = .named,
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
                        .kind = .named,
                        .name_override = null,
                        .alias = .none,
                        .default_value = null,
                        .config = {},
                        .help = "A single argument",
                    },
                },
            };
        };
    };

    const parser_tester = ParserTester(TestCmd, TestCmd.cmd_info);
    const expectParsed = parser_tester.expectParsed;
    const expectHelp = parser_tester.expectHelp;

    try expectParsed(&.{}, .{
        .log_level = .debug,
        .metrics_port = 12345,
        .subcmd = null,
    });

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

    try expectParsed(&.{ "gossip", "foo/bar.zig" }, .{
        .log_level = .debug,
        .metrics_port = 12345,
        .subcmd = .{
            .gossip = .{
                .file_path = "foo/bar.zig",
                .gossip_port = 8020,
                .entrypoints = &.{},
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
        \\  sig-test gossip [file] [OPTIONS]
        \\
        \\Run gossip
        \\
        \\Sub-Test CLI
        \\
        \\OPTIONS:
        \\  [file]                               Input file
        \\
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
        \\      --single   A single argument
        \\  -h, --help     Prints help information
        \\
    );
}

// -- IMPLEMENTATION DETAILS -- //

inline fn isArgumentInfo(comptime T: type) bool {
    comptime {
        if (@typeInfo(T) != .@"struct") return false;
        if (!@hasDecl(T, "Argument")) return false;
        if (@TypeOf(&T.Argument) != *const type) return false;
        return ArgumentInfo(T.Argument) == T;
    }
}

fn ArgumentConfig(comptime Arg: type) type {
    return switch (@typeInfo(Arg)) {
        .pointer => |p_info| blk: {
            if (p_info.size != .slice) {
                @compileError("Cannot have non-slice pointer arguments");
            }

            if (p_info.child == u8) break :blk BytesConfig;
            const SubConfig = ArgumentConfig(p_info.child);

            // []const []const u8 is always a list of strings
            if (SubConfig == BytesConfig) break :blk BytesConfig.StringOnly;

            break :blk SubConfig;
        },
        .optional => |o_info| blk: {
            switch (@typeInfo(o_info.child)) {
                .optional => {
                    @compileError("Cannot have optional optional arguments");
                },
                .pointer => |p_info| if (p_info.size == .slice and p_info.child != u8) {
                    @compileError("Cannot have optional list arguments;" ++
                        " an unspecified list is simply empty");
                },
                else => {},
            }

            const SubConfig = ArgumentConfig(o_info.child);

            // ?[]const u8 is always an optional string
            if (SubConfig == BytesConfig) break :blk BytesConfig.StringOnly;

            break :blk SubConfig;
        },
        .int, .@"enum", .bool => void,
        else => @compileError("Unexpected argument type: " ++ @typeName(Arg)),
    };
}

const ALIAS_TABLE_IDX_BASE = 'A';
const MAX_ALIAS_TABLE_LEN = 'z' + 1 - 'A';

const ArgStructIndex = struct {
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
        .@"struct" => |cmd_s_info| cmd_s_info.fields,
        .void => &.{},
        else => unreachable,
    };

    const cmd_and_arg_basic_info = computeCmdAndArgBasicInfo(Cmd, maybe_parent_name);
    const argument_count = cmd_and_arg_basic_info.argument_count;
    const maybe_sub_cmd_s_field_index = cmd_and_arg_basic_info.maybe_sub_cmd_s_field_index;

    const ArgEnumInt = std.math.IntFittingRange(
        0,
        argument_count -| 1,
    );
    const ArgEnumIntPlusOne = std.math.IntFittingRange(0, argument_count);
    const alias_table_sentinel: ArgEnumIntPlusOne = argument_count;

    const ArgEnum: type, //
    const arg_enum_to_field_map: []const ArgStructIndex, //
    const positional_set: []const ArgStructIndex, //
    // WIP table that will be used to construct a final table for mapping aliases to arguments
    const alias_table_wip: [MAX_ALIAS_TABLE_LEN]ArgEnumIntPlusOne, //
    // partially default-initialised result
    const default_init: Cmd //
    = mappings_and_init: {
        var arg_enum_fields: []const Type.EnumField = &.{};
        var arg_enum_to_field_map: []const ArgStructIndex = &.{};
        var positional_set: []const ArgStructIndex = &.{};

        var alias_table_wip = [_]ArgEnumIntPlusOne{alias_table_sentinel} ** MAX_ALIAS_TABLE_LEN;

        var default_init: Cmd = undefined;

        const helper = struct {
            /// shared logic for each argument field, and each argument group field.
            fn computeArgFieldInfo(
                comptime is_last: bool,

                //
                comptime field_name: []const u8,
                comptime FieldType: type,
                comptime arg_info: ArgumentInfo(FieldType),

                //
                comptime arg_enum_fields_ptr: *@TypeOf(arg_enum_fields),

                //
                comptime arg_struct_index: ArgStructIndex,
                comptime arg_enum_to_field_map_ptr: *@TypeOf(arg_enum_to_field_map),
                comptime positional_set_ptr: *@TypeOf(positional_set),

                //
                comptime default_init_ptr: anytype,

                //
                comptime alias_table_wip_ptr: *@TypeOf(alias_table_wip),
            ) void {
                const arg_enum_field_name = (arg_info.name_override orelse field_name) ++ "";
                if (constEql(arg_enum_field_name, "help")) @compileError(
                    "Cannot use reserved argument name " ++ parent_prefix ++ "help",
                );

                const is_slice = switch (@typeInfo(FieldType)) {
                    .pointer => |ptr_info| switch (ptr_info.size) {
                        .slice => ptr_info.child != u8 or arg_info.config == .list,
                        else => false,
                    },
                    else => false,
                };

                switch (arg_info.kind) {
                    .named => {
                        const arg_enum_field_idx = arg_enum_fields_ptr.len;
                        arg_enum_fields_ptr.* = arg_enum_fields_ptr.* ++ .{Type.EnumField{
                            .name = arg_enum_field_name,
                            .value = arg_enum_field_idx,
                        }};

                        if (arg_info.alias != .none) {
                            const idx = @intFromEnum(arg_info.alias) - ALIAS_TABLE_IDX_BASE;
                            alias_table_wip_ptr[idx] = arg_enum_field_idx;
                        }

                        arg_enum_to_field_map_ptr.* =
                            arg_enum_to_field_map_ptr.* ++ .{arg_struct_index};
                    },
                    .positional => {
                        if (maybe_sub_cmd_s_field_index != null) @compileError(
                            "Cannot have a positional argument" ++
                                " (" ++ parent_prefix ++ field_name ++ ")" ++
                                " and a sub-command" ++
                                " (" ++ parent_prefix ++ field_name ++ ")",
                        );

                        if (is_slice and !is_last) @compileError(
                            "Argument " ++ parent_prefix ++ field_name ++
                                " cannot be both a list and a positional if it is not last.",
                        );

                        if (arg_info.alias != .none) @compileError(
                            "Argument " ++
                                parent_prefix ++ field_name ++
                                " cannot have an alias, " ++
                                "since it's not named, it's positional",
                        );

                        positional_set_ptr.* =
                            positional_set_ptr.* ++ .{arg_struct_index};
                    },
                }

                if (is_slice) {
                    // default init lists to empty.
                    @field(default_init_ptr, field_name) = &.{};
                }

                const default_value = arg_info.default_value;
                @field(default_init_ptr, field_name) = default_value;

                if (is_slice and default_value.len != 0 and
                    @TypeOf(default_value[0]) != u8) @compileError(
                    "Don't default initialize slice field with a buffer: " ++
                        parent_prefix ++ field_name,
                );
            }
        };

        @setEvalBranchQuota(cmd_fields.len * 3 + 1);
        for (cmd_fields, 0..) |s_field, s_field_i| {
            if (@typeInfo(s_field.type) == .@"union" or
                (@typeInfo(s_field.type) == .optional and
                    @typeInfo(@typeInfo(s_field.type).optional.child) == .@"union"))
            {
                continue;
            }

            const maybe_arg_info = @field(cmd_info.sub, s_field.name);
            if (isArgumentInfo(@TypeOf(maybe_arg_info))) {
                helper.computeArgFieldInfo(
                    s_field_i == cmd_fields.len - 1,
                    s_field.name,
                    s_field.type,
                    maybe_arg_info,

                    &arg_enum_fields,

                    .{ .index = s_field_i, .sub = null },
                    &arg_enum_to_field_map,
                    &positional_set,

                    &default_init,

                    &alias_table_wip,
                );
                continue;
            }

            // handle `ArgumentInfoGroup`
            const s_sub_info = @typeInfo(s_field.type).@"struct";
            @setEvalBranchQuota(cmd_fields.len * 3 + 1 + s_sub_info.fields.len * 2 + 1);
            for (s_sub_info.fields, 0..) |s_sub_field, s_sub_field_i| {
                helper.computeArgFieldInfo(
                    s_field_i == cmd_fields.len - 1 and
                        s_sub_field_i == s_sub_info.fields.len - 1,

                    s_sub_field.name,
                    s_sub_field.type,
                    @field(maybe_arg_info, s_sub_field.name),

                    &arg_enum_fields,

                    .{ .index = s_field_i, .sub = s_sub_field_i },
                    &arg_enum_to_field_map,
                    &positional_set,

                    &@field(default_init, s_field.name),

                    &alias_table_wip,
                );
            }

            if (positional_set.len != 0) if (maybe_sub_cmd_s_field_index) |sub_cmd_s_field_index| {
                const sub_cmd_s_field_info = cmd_fields[sub_cmd_s_field_index];
                const sub_cmd_s_field_name = sub_cmd_s_field_info.name;

                const pos_name = blk: {
                    const pos_s_field_idx = positional_set[0];
                    const pos_s_field = cmd_fields[pos_s_field_idx.index];
                    const s_sub_field_idx = pos_s_field_idx.sub orelse break :blk pos_s_field.name;
                    const s_sub_fields = @typeInfo(pos_s_field.type).@"struct".fields;
                    const s_sub_field = s_sub_fields[s_sub_field_idx];
                    break :blk s_sub_field.name;
                };

                @compileError(
                    "" ++
                        parent_name ++ " cannot have both a " ++
                        "subcommand (" ++ sub_cmd_s_field_name ++ ") " ++
                        "and a positional (" ++ pos_name ++ ")",
                );
            };
        }

        const ArgEnum = @Type(.{ .@"enum" = .{
            .tag_type = ArgEnumInt,
            .fields = arg_enum_fields,
            .decls = &.{},
            .is_exhaustive = true,
        } });

        break :mappings_and_init .{
            ArgEnum,
            arg_enum_to_field_map,
            positional_set,
            alias_table_wip,
            default_init,
        };
    };
    const arg_enum_fields = @typeInfo(ArgEnum).@"enum".fields;

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
            .@"union" => CmdMaybeUnion,
            .optional => |o_info| o_info.child,
            else => unreachable,
        };
        const u_info = @typeInfo(CmdUnion).@"union";

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
        if (arg_enum_fields.len == 0) break :alias_info .{ 0, false };

        const ArgEnumIntVec = @Vector(MAX_ALIAS_TABLE_LEN, ArgEnumIntPlusOne);
        const sentinel_vec: ArgEnumIntVec = @splat(alias_table_sentinel);
        const used_aliases_mask_vec = alias_table_wip != sentinel_vec;

        const UsedAliasesBits = @Type(.{ .int = .{
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

    const alias_table: [alias_table_len]ArgEnumIntPlusOne = alias_table_wip[0..alias_table_len].*;

    return struct {
        fn freeImpl(allocator: std.mem.Allocator, args: Cmd) void {
            freeArguments(allocator, args);
            const sub_cmd_s_field_index = maybe_sub_cmd_s_field_index orelse return;

            const sub_cmd_s_field_info = cmd_fields[sub_cmd_s_field_index];
            const sub_cmd_s_field_name = sub_cmd_s_field_info.name;
            const sub_cmd_info_map = @field(cmd_info.sub, sub_cmd_s_field_name);
            const maybe_cmd_field_value = @field(args, sub_cmd_s_field_name);
            const cmd_field_value = maybe_cmd_field_value orelse return;

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

        fn freeArguments(allocator: std.mem.Allocator, partial_args: Cmd) void {
            @setEvalBranchQuota(arg_enum_to_field_map.len * 8 + 1);
            inline for (arg_enum_to_field_map) |s_field_idx| {
                const s_field = cmd_fields[s_field_idx.index];
                const maybe_target_field = @field(partial_args, s_field.name);
                const target_field = blk: {
                    const s_sub_field_idx = s_field_idx.sub orelse break :blk maybe_target_field;
                    const s_sub_fields = @typeInfo(s_field.type).@"struct".fields;
                    const s_sub_field = s_sub_fields[s_sub_field_idx];
                    break :blk @field(maybe_target_field, s_sub_field.name);
                };
                const ptr_info = switch (@typeInfo(@TypeOf(target_field))) {
                    .pointer => |ptr_info| ptr_info,
                    else => continue,
                };
                if (ptr_info.size != .slice) continue;
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
            help_writer: AdaptedHelpWriter,
            args_iter: *ArgsIter,
        ) ParseCmdError!?Cmd {
            var result: Cmd = default_init;
            errdefer freeArguments(allocator, result);

            var positional_count: std.math.IntFittingRange(0, positional_set.len) = 0;

            const parse_result: union(enum) {
                help,
                subcmd_set: if (maybe_sub_cmd_s_field_index != null) void else noreturn,
                subcmd_unset,
            } = while (args_iter.next()) |arg| {
                if (arg.len == 0) continue;

                parse_arg: {
                    const key, //
                    const maybe_value //
                    = try parseArgumentKeyMaybeValStr(arg) orelse break :parse_arg;

                    // prevent trying to parse any more positionals
                    positional_count = positional_set.len;

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

                    const arg_tag: ArgEnum = switch (key) {
                        .short => |alias| argumentTagFromAlias(alias) orelse
                            return error.UnrecognizedArgumentAlias,
                        .long => |name| argumentTagFromName(name) orelse
                            return error.UnrecognizedArgumentName,
                    };

                    switch (arg_tag) {
                        inline else => |itag| {
                            const s_field_idx = arg_enum_to_field_map[@intFromEnum(itag)];
                            try parseArgValueMaybeScanIntoResult(
                                allocator,
                                s_field_idx,
                                &result,
                                maybe_value,
                                args_iter,
                            );
                        },
                    }

                    continue;
                }

                if (positional_count != positional_set.len) {
                    @setEvalBranchQuota(positional_set.len);
                    switch (positional_count) {
                        inline 0...positional_set.len - 1 => |positional_i| {
                            const s_field_idx = positional_set[positional_i];

                            const args_iter_index_guard = args_iter.index;
                            try parseArgValueMaybeScanIntoResult(
                                allocator,
                                s_field_idx,
                                &result,
                                arg,
                                args_iter,
                            );
                            std.debug.assert( // sanity check
                                args_iter.index ==
                                    args_iter_index_guard //
                            );

                            positional_count += 1;
                            continue;
                        },
                        else => unreachable,
                    }
                }

                const sub_cmd_s_field_index = maybe_sub_cmd_s_field_index orelse {
                    return error.UnexpectedPositional;
                };
                const sub_cmd_s_field_info = cmd_fields[sub_cmd_s_field_index];
                const sub_cmd_s_field_name = sub_cmd_s_field_info.name;
                const CmdMaybeUnion = sub_cmd_s_field_info.type;

                const sub_cmd_info_map = @field(cmd_info.sub, sub_cmd_s_field_name);
                const CmdUnion = switch (@typeInfo(CmdMaybeUnion)) {
                    .@"union" => @compileError(
                        "The subcommand field " ++ parent_prefix ++ sub_cmd_s_field_name ++
                            " must be optional.",
                    ),
                    .optional => |o_info| o_info.child,
                    else => unreachable,
                };

                const CmdEnum = @typeInfo(CmdUnion).@"union".tag_type.?;
                const cmd_tag = enumFromStringAfterReplacingScalarInTag(
                    arg,
                    CmdEnum,
                    '_',
                    '-',
                ) orelse return error.UnrecognizedCommand;

                const maybe_cmd_field_ptr = &@field(result, sub_cmd_s_field_name);
                const cmd_field_ptr = blk: {
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
                    freeArguments(allocator, result);
                    return null;
                },
                .subcmd_set => comptime std.debug.assert(maybe_sub_cmd_s_field_index != null),
                .subcmd_unset => if (maybe_sub_cmd_s_field_index) |sub_cmd_s_field_index| {
                    const sub_cmd_s_field_info = cmd_fields[sub_cmd_s_field_index];
                    const sub_cmd_s_field_name = sub_cmd_s_field_info.name;
                    @field(result, sub_cmd_s_field_name) = null;
                },
            }

            return result;
        }

        fn parseArgValueMaybeScanIntoResult(
            allocator: std.mem.Allocator,
            comptime s_field_idx: ArgStructIndex,
            result: *Cmd,
            maybe_value: ?[]const u8,
            args_iter: *ArgsIter,
        ) !void {
            const s_field = cmd_fields[s_field_idx.index];
            const s_field_ptr = &@field(result, s_field.name);
            const maybe_arg_info = @field(cmd_info.sub, s_field.name);

            const arg_name, const arg_ptr, const arg_info = arg: {
                const s_sub_field_idx = s_field_idx.sub orelse break :arg .{
                    s_field.name,
                    s_field_ptr,
                    maybe_arg_info,
                };
                const s_sub_fields = @typeInfo(s_field.type).@"struct".fields;
                const s_sub_field = s_sub_fields[s_sub_field_idx];
                const s_sub_field_ptr = &@field(s_field_ptr, s_sub_field.name);
                break :arg .{
                    s_sub_field.name,
                    s_sub_field_ptr,
                    @field(maybe_arg_info, s_sub_field.name),
                };
            };

            const Arg = @TypeOf(arg_ptr.*);
            const is_list, const ValueType = switch (@typeInfo(Arg)) {
                .pointer => |ptr_info| blk: {
                    const is_list = ptr_info.size == .slice and
                        (ptr_info.child != u8 or arg_info.config == .list);
                    const ListElem = if (is_list) ptr_info.child else Arg;
                    break :blk .{ is_list, ListElem };
                },
                else => .{ false, Arg },
            };
            const parsed_value = try parseSingleArgValueMaybeScan(
                arg_name,
                ValueType,
                maybe_value,
                args_iter,
            );
            if (!is_list) {
                arg_ptr.* = parsed_value;
            } else {
                arg_ptr.* = try allocator.realloc(
                    @constCast(arg_ptr.*),
                    arg_ptr.len + 1,
                );
                @constCast(&arg_ptr.*[arg_ptr.len - 1]).* = parsed_value;
            }
        }

        const AdaptedHelpWriter = std.io.GenericWriter(
            std.io.AnyWriter,
            error{HelpWriteFail},
            struct {
                fn adaptedWriteFn(
                    unadapted: std.io.AnyWriter,
                    bytes: []const u8,
                ) error{HelpWriteFail}!usize {
                    return unadapted.write(bytes) catch return error.HelpWriteFail;
                }
            }.adaptedWriteFn,
        );
        fn adaptedSetColor(
            writer_adapted: AdaptedHelpWriter,
            tty_config: std.io.tty.Config,
            color: std.io.tty.Color,
        ) WriteHelpError!void {
            tty_config.setColor(writer_adapted, color) catch |err| switch (err) {
                error.HelpWriteFail => |e| return e,
                error.Unexpected => return error.TtyFail,
            };
        }

        fn writeHelp(
            /// `*const [n][]const u8`
            command_chain: anytype,
            tty: std.io.tty.Config,
            writer: AdaptedHelpWriter,
        ) WriteHelpError!void {
            try adaptedSetColor(writer, tty, .yellow);
            try writer.writeAll("USAGE:\n");
            try writer.writeByteNTimes(' ', 2);

            try adaptedSetColor(writer, tty, .green);
            try writer.writeAll(command_chain[0]);
            try writer.writeByte(' ');
            for (command_chain[1..]) |subcmd_str| {
                try writer.writeAll(subcmd_str);
                try writer.writeByte(' ');
            }

            @setEvalBranchQuota(positional_set.len * 8 + 1);
            inline for (positional_set) |s_field_idx| {
                const s_field = cmd_fields[s_field_idx.index];
                const maybe_arg_info = @field(cmd_info.sub, s_field.name);
                const arg_name = blk: {
                    const s_sub_field_idx = s_field_idx.sub orelse {
                        const arg_info: ArgumentInfo(s_field.type) = maybe_arg_info;
                        break :blk comptimeReplaceScalar(
                            arg_info.name_override orelse s_field.name,
                            '_',
                            '-',
                        );
                    };
                    const s_sub_fields = @typeInfo(s_field.type).@"struct".fields;
                    const s_sub_field = s_sub_fields[s_sub_field_idx];
                    const arg_info: ArgumentInfo(s_sub_field.type) =
                        @field(maybe_arg_info, s_sub_field.name);
                    break :blk comptimeReplaceScalar(
                        arg_info.name_override orelse s_sub_field.name,
                        '_',
                        '-',
                    );
                };

                try writer.writeAll("[" ++ arg_name ++ "] ");
            }

            try writer.writeAll("[OPTIONS]");

            try adaptedSetColor(writer, tty, .reset);
            try writer.writeByteNTimes('\n', 2);
            try writer.writeAll(cmd_info.help.short);

            if (cmd_info.help.long) |long_help| {
                try writer.writeByteNTimes('\n', 2);
                try writer.writeAll(long_help);
            }

            try writer.writeByte('\n');

            if (maybe_subcmd_list) |subcmd_list| {
                try writer.writeByte('\n');

                try adaptedSetColor(writer, tty, .yellow);
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

                    try adaptedSetColor(writer, tty, .green);
                    try writer.writeByte('\n');
                    try writer.writeByteNTimes(' ', 2);

                    try writer.writeAll(subcmd_name);
                    const padding = name_base_width - subcmd_name.len + 3;
                    try adaptedSetColor(writer, tty, .reset);
                    try writer.writeByteNTimes(' ', padding);

                    const indent = 2 + name_base_width + 3;
                    try writeIndentedText(writer, indent, subcmd_short_help);
                }

                try writer.writeByte('\n');
            }

            try writer.writeByte('\n');

            try adaptedSetColor(writer, tty, .yellow);
            try writer.writeAll("OPTIONS:");

            const name_alias_base_width: u64, //
            const default_value_base_width: ?u64 //
            = try writeArgumentsHelp(.no_color, .{ .context = std.io.null_writer.any() }, 0, null);

            _ = try writeArgumentsHelp(
                tty,
                writer,
                name_alias_base_width,
                default_value_base_width,
            );
        }

        fn writeArgumentsHelp(
            tty: std.io.tty.Config,
            writer: AdaptedHelpWriter,
            name_alias_base_width: u64,
            default_value_base_width: ?u64,
        ) !struct {
            u64, // max_name_alias_width
            ?u64, // max_default_value_width
        } {
            const help_argument_alias_name = "-h, --help";

            var max_name_alias_width: u64 = @max(
                help_argument_alias_name.len,
                name_alias_base_width,
            );
            var max_default_value_width: ?u64 = null;

            @setEvalBranchQuota(positional_set.len * 8 + 1);
            inline for (positional_set, 0..) |s_field_idx, i| {
                const s_field = cmd_fields[s_field_idx.index];
                const maybe_arg_info = @field(cmd_info.sub, s_field.name);
                const arg_info, const arg_name = blk: {
                    const s_sub_field_idx = s_field_idx.sub orelse {
                        const arg_info: ArgumentInfo(s_field.type) = maybe_arg_info;
                        break :blk .{ arg_info, arg_info.name_override orelse s_field.name };
                    };
                    const s_sub_fields = @typeInfo(s_field.type).@"struct".fields;
                    const s_sub_field = s_sub_fields[s_sub_field_idx];
                    const arg_info: ArgumentInfo(s_sub_field.type) =
                        @field(maybe_arg_info, s_sub_field.name);
                    break :blk .{ arg_info, arg_info.name_override orelse s_sub_field.name };
                };

                const multiline_help = std.mem.indexOfScalar(u8, arg_info.help, '\n') != null;

                try adaptedSetColor(writer, tty, .green);
                if (multiline_help) try writer.writeByte('\n');
                try writer.writeByte('\n');
                try writer.writeByteNTimes(' ', 2);

                // write argument alias & name
                var cw = std14.countingWriter(writer);
                try writeArgumentNameWithDefault(null, arg_name, cw.writer());
                max_name_alias_width = @max(max_name_alias_width, cw.bytes_written);

                // write padding
                try adaptedSetColor(writer, tty, .reset);
                try writer.writeByteNTimes(
                    ' ',
                    @max(cw.bytes_written, name_alias_base_width) - cw.bytes_written + 2,
                );

                // maybe write default value
                cw.bytes_written = 0;
                if (try renderArgumentDefaultValue(arg_info.default_value, cw.writer())) {
                    max_default_value_width = @max(
                        max_default_value_width orelse 0,
                        cw.bytes_written,
                    );
                }

                // write padding
                try writer.writeByteNTimes(' ', 1 + padding: {
                    const base_width = default_value_base_width orelse break :padding 0;
                    break :padding base_width - cw.bytes_written + 2;
                });

                // write help description and newline
                const indent = 2 + name_alias_base_width + 2 +
                    if (default_value_base_width) |base_width| (base_width + 3) else 1;
                try writeIndentedText(writer, indent, arg_info.help);
                if (multiline_help and i != positional_set.len - 1) try writer.writeByte('\n');
            }

            if (positional_set.len != 0) try writer.writeByte('\n');

            @setEvalBranchQuota(arg_enum_to_field_map.len * 8 + 1);
            inline for (arg_enum_to_field_map, 0..arg_enum_fields.len) |s_field_idx, e_int| {
                const arg_tag: ArgEnum = @enumFromInt(e_int);
                const s_field = cmd_fields[s_field_idx.index];
                const maybe_arg_info = @field(cmd_info.sub, s_field.name);
                const arg_info = if (s_field_idx.sub) |s_sub_field_idx| blk: {
                    const s_sub_fields = @typeInfo(s_field.type).@"struct".fields;
                    const s_sub_field = s_sub_fields[s_sub_field_idx];
                    break :blk @field(maybe_arg_info, s_sub_field.name);
                } else @as(ArgumentInfo(s_field.type), maybe_arg_info);

                const multiline_help = std.mem.indexOfScalar(u8, arg_info.help, '\n') != null;

                // write indent and separating newlines
                try adaptedSetColor(writer, tty, .green);
                if (multiline_help) try writer.writeByte('\n');
                try writer.writeByte('\n');
                try writer.writeByteNTimes(' ', 2);

                // write argument alias & name
                var cw = std14.countingWriter(writer);
                try writeArgumentNameWithDefault(
                    arg_info.alias,
                    @tagName(arg_tag),
                    cw.writer(),
                );
                max_name_alias_width = @max(max_name_alias_width, cw.bytes_written);

                // write padding
                try adaptedSetColor(writer, tty, .reset);
                try writer.writeByteNTimes(
                    ' ',
                    @max(cw.bytes_written, name_alias_base_width) - cw.bytes_written + 2,
                );

                // maybe write default value
                cw.bytes_written = 0;
                if (try renderArgumentDefaultValue(arg_info.default_value, cw.writer())) {
                    max_default_value_width = @max(
                        max_default_value_width orelse 0,
                        cw.bytes_written,
                    );
                }

                // write padding
                try writer.writeByteNTimes(' ', 1 + padding: {
                    const base_width = default_value_base_width orelse break :padding 0;
                    break :padding base_width - cw.bytes_written + 2;
                });

                // write help description and newline
                const indent = 2 + name_alias_base_width + 2 +
                    if (default_value_base_width) |base_width| (base_width + 3) else 1;
                try writeIndentedText(writer, indent, arg_info.help);
                if (multiline_help) try writer.writeByte('\n');
            }

            try adaptedSetColor(writer, tty, .green);
            try writer.writeByte('\n');
            try writer.writeByteNTimes(' ', 2);

            try writer.writeAll(help_argument_alias_name);
            const padding1 =
                @max(help_argument_alias_name.len, name_alias_base_width) -
                help_argument_alias_name.len + 3 -
                @intFromBool(default_value_base_width != null);
            const padding2 = if (default_value_base_width) |base_width| base_width + 3 else 0;

            try adaptedSetColor(writer, tty, .reset);
            try writer.writeByteNTimes(' ', padding1 + padding2);

            try writer.writeAll("Prints help information\n");

            return .{
                max_name_alias_width,
                max_default_value_width,
            };
        }

        inline fn argumentTagFromAlias(alias: u8) ?ArgEnum {
            if (alias_table.len == 0) return null;

            if (alias < ALIAS_TABLE_IDX_BASE) return null;
            if (alias - ALIAS_TABLE_IDX_BASE >= alias_table.len) return null;

            const value = alias_table[alias - ALIAS_TABLE_IDX_BASE];
            if (alias_table_has_holes and value == alias_table_sentinel) return null;
            return @enumFromInt(value);
        }

        inline fn argumentTagFromName(name: []const u8) ?ArgEnum {
            if (arg_enum_fields.len == 0) return null;
            return enumFromStringAfterReplacingScalarInTag(name, ArgEnum, '_', '-');
        }
    };
}

/// compute the sub-info struct and some basic facts about the argument fields
/// that don't require the sub-info to be defined.
fn computeCmdAndArgBasicInfo(
    comptime T: type,
    comptime maybe_parent_name: ?[]const u8,
) struct {
    SubInfo: type,
    argument_count: usize,
    maybe_sub_cmd_s_field_index: ?usize,
} {
    const parent_name = maybe_parent_name orelse "root";

    const s_info = switch (@typeInfo(T)) {
        .@"struct" => |s_info| s_info,
        .void => @typeInfo(struct {}).@"struct",
        else => unreachable,
    };

    var arg_count: usize = 0;
    var fields: [s_info.fields.len]std.builtin.Type.StructField = undefined;
    var maybe_sub_cmd_s_field_index: ?usize = null;

    @setEvalBranchQuota(s_info.fields.len * 2 + 1);
    for (&fields, s_info.fields, 0..) |*new_s_field, s_field, s_field_i| {
        const UnwrappedStructFieldType = switch (@typeInfo(s_field.type)) {
            .optional => |o_info| switch (@typeInfo(o_info.child)) {
                .@"union" => o_info.child,
                else => s_field.type,
            },
            else => s_field.type,
        };

        const FieldType = switch (@typeInfo(UnwrappedStructFieldType)) {
            .@"union" => |sub_u_info| sub_infos: {
                if (maybe_sub_cmd_s_field_index) |prev| @compileError(
                    "Cannot have two sub-command union fields in " ++ parent_name ++ ": " ++
                        s_info.fields[prev].name ++ " & " ++ s_field.name,
                );

                maybe_sub_cmd_s_field_index = s_field_i;

                @setEvalBranchQuota(
                    s_info.fields.len * 2 + 1 +
                        sub_u_info.fields.len * 2 + 1,
                );
                break :sub_infos UnionArgDescSubMap(UnwrappedStructFieldType);
            },
            .@"struct" => |s_sub_info| sub_map: {
                arg_count += s_sub_info.fields.len;
                @setEvalBranchQuota(
                    s_info.fields.len * 2 + 1 +
                        s_sub_info.fields.len * 2 + 1,
                );
                break :sub_map ArgumentInfoGroup(UnwrappedStructFieldType);
            },
            else => arg_info: {
                arg_count += 1;
                break :arg_info ArgumentInfo(UnwrappedStructFieldType);
            },
        };

        new_s_field.* = .{
            .name = s_field.name,
            .type = FieldType,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    const SubInfo = @Type(.{ .@"struct" = .{
        .layout = .auto,
        .backing_integer = null,
        .fields = &fields,
        .is_tuple = false,
        .decls = &.{},
    } });
    return .{
        .SubInfo = SubInfo,
        .argument_count = arg_count,
        .maybe_sub_cmd_s_field_index = maybe_sub_cmd_s_field_index,
    };
}

fn UnionArgDescSubMap(comptime U: type) type {
    const sub_u_info = @typeInfo(U).@"union";
    var new_s_fields: [sub_u_info.fields.len]std.builtin.Type.StructField = undefined;

    for (&new_s_fields, sub_u_info.fields) |*new_s_field, u_field| {
        new_s_field.* = .{
            .name = u_field.name,
            .type = CommandInfo(u_field.type),
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{ .@"struct" = .{
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

const ArgumentKeyNameOrAlias = union(enum) {
    short: u8,
    long: []const u8,
};

const ParseArgumentKeyMaybeValStrError = error{
    UnexpectedSingleDash,
    AliasMissingEql,
    MissingValueAfterEqual,
    UnexpectedDoubleDash,
};

/// Parses `-{c}`, `--{name}`, optionally followed by `={value}`.
/// Returns null if `arg[0] != '-'`.
fn parseArgumentKeyMaybeValStr(
    arg: []const u8,
) ParseArgumentKeyMaybeValStrError!?struct {
    ArgumentKeyNameOrAlias,
    ?[]const u8,
} {
    if (arg[0] != '-') return null;
    if (arg.len == 1) return error.UnexpectedSingleDash;

    if (arg[1] != '-') { // '-{c}'
        const key: ArgumentKeyNameOrAlias = .{ .short = arg[1] };
        if (arg.len == 2) return .{ key, null };
        if (arg[2] != '=') return error.AliasMissingEql;
        if (arg.len == 3) return error.MissingValueAfterEqual;
        return .{ key, arg[3..] };
    }

    if (arg.len == 2) return error.UnexpectedDoubleDash;

    const maybe_eql_idx = std.mem.indexOfScalarPos(u8, arg, 2, '=');
    const arg_name_str = arg[2 .. maybe_eql_idx orelse arg.len];
    const key: ArgumentKeyNameOrAlias = .{ .long = arg_name_str };

    const maybe_val = if (maybe_eql_idx) |eql_idx| arg[eql_idx + 1 ..] else null;
    if (maybe_val) |val| if (val.len == 0) return error.MissingValueAfterEqual;
    return .{ key, maybe_val };
}

fn parseSingleArgValueMaybeScan(
    comptime argument_name: []const u8,
    comptime T: type,
    maybe_value: ?[]const u8,
    args_iter: *ArgsIter,
) ParseSingleArgValueError!T {
    return parseSingleArgValue(argument_name, T, maybe_value) catch |err| switch (err) {
        error.MissingValue => parseSingleArgValue(argument_name, T, args_iter.next()),
        else => |e| return e,
    };
}

const ParseSingleArgValueError = error{
    UnexpectedValueForFlag,
    MissingValue,
    InvalidValue,
};

fn parseSingleArgValue(
    comptime arg_name: []const u8,
    comptime T: type,
    maybe_value: ?[]const u8,
) ParseSingleArgValueError!T {
    if (T == []const u8) {
        return maybe_value orelse return error.MissingValue;
    }

    switch (@typeInfo(T)) {
        .bool => {
            const value_str = maybe_value orelse return true;
            if (std.mem.eql(u8, value_str, "true")) return true;
            if (std.mem.eql(u8, value_str, "false")) return false;
            return error.InvalidValue;
        },
        .int => {
            const value_str = maybe_value orelse return {
                return error.MissingValue;
            };
            return std.fmt.parseInt(T, value_str, 0) catch {
                return error.InvalidValue;
            };
        },
        .@"enum" => {
            const value_str = maybe_value orelse return {
                return error.MissingValue;
            };
            return std.meta.stringToEnum(T, value_str) orelse {
                return error.InvalidValue;
            };
        },
        .optional => |optional| if (@typeInfo(optional.child) != .optional) {
            return try parseSingleArgValue(arg_name, optional.child, maybe_value);
        },
        else => {},
    }

    @compileError("Unexpected argument type: " ++ arg_name ++ ": " ++ @typeName(T));
}

/// Writes `"-?, --{name}"`, or `"    --{name}"`.
/// Replaces all '_' in `name` with '-'.
fn writeArgumentNameWithDefault(
    /// Null for positionals
    maybe_arg_alias: ?ArgumentAlias,
    arg_name: []const u8,
    /// `std.io.GenericWriter(...)` | `std.io.AnyWriter`
    writer: anytype,
) @TypeOf(writer).Error!void {
    if (maybe_arg_alias) |arg_alias| {
        if (arg_alias != .none) {
            try writer.print("-{c}, ", .{@intFromEnum(arg_alias)});
        } else {
            try writer.writeByteNTimes(' ', 4);
        }
        try writer.writeByteNTimes('-', 2);
    } else {
        try writer.writeByte('[');
    }

    var start_idx: usize = 0;
    while (std.mem.indexOfScalarPos(u8, arg_name, start_idx, '_')) |end_idx| {
        defer start_idx = end_idx + 1;
        try writer.writeAll(arg_name[start_idx..end_idx]);
        try writer.writeByte('-');
    }
    try writer.writeAll(arg_name[start_idx..]);
    if (maybe_arg_alias == null) {
        try writer.writeByte(']');
    }
}

/// Returns true only if the value was rendered.
inline fn renderArgumentDefaultValue(
    comptime default_value: anytype,
    /// `std.io.GenericWriter(...)` | `std.io.AnyWriter`
    writer: anytype,
) !bool {
    const T = @TypeOf(default_value);
    const value, const fmt_str = if (T == []const u8)
        .{ std.zig.fmtEscapes(default_value), "" }
    else switch (@typeInfo(T)) {
        .bool => .{ default_value, "any" },
        .@"enum" => .{ @tagName(default_value), "s" },
        .int => .{ default_value, "d" },
        .optional => |optional| {
            if (@typeInfo(optional.child) == .optional) return false;
            return renderArgumentDefaultValue(default_value orelse return false, writer);
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
    const e_info = @typeInfo(E).@"enum";
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
/// This is both a minor optimization for comparing against constant-length strings at runtime,
/// as well as a way to compare strings at comptime whilst consuming only a single unit of
/// eval branch quota (1 for the function call) - ie, a comptime optimization.
inline fn constEql(a: []const u8, b: []const u8) bool {
    const a_is_const = @typeInfo(@TypeOf(.{a.len})).@"struct".fields[0].is_comptime;
    const b_is_const = @typeInfo(@TypeOf(.{b.len})).@"struct".fields[0].is_comptime;
    if (!a_is_const and !b_is_const) @compileError("Neither a nor b is of constant length");

    if (a.len != b.len) return false;
    const len = if (a_is_const) a.len else if (b_is_const) b.len else unreachable;

    const a_vec: @Vector(len, u8) = a[0..len].*;
    const b_vec: @Vector(len, u8) = b[0..len].*;
    return @reduce(.And, a_vec == b_vec);
}
