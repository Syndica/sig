# Generated Docs

1. Run `zig build docs`.

2. Serve the generated files, for example:

```sh
python -m http.server -b 127.0.0.1 8000 -d zig-out/docs
```

# Running Shred Receive

1. Use Agave to create a leader schedule text file:

```sh
solana leader-schedule > schedule.txt
```

2. Start v2 with the checked in example runtime config:

```sh
zig build run -- config/example.zon
```

`config/example.zon` shows the fields accepted by the runtime config and example values for running the current v2 topology. It is loaded as the `Config` type in `init/main.zig`. It controls values such as ports, cluster, telemetry settings, file paths, and memory sizes. It does not define service topology.

# Running with Tracy

1. Build with `-Denable-tracy`.

2. Use `.sandboxing_mode = .threaded` in your runtime config.

# Linting

Run v2 lint checks from this directory:

```sh
zig build lint
```

Pass explicit linter args after `--`:

```sh
zig build lint -- --fix
```

# Topology

v2 runs each service as an isolated process, or as a thread when `.sandboxing_mode = .threaded` is used. The parent process creates shared memory regions before spawning services, then maps each region into the services that need it. Services communicate through those shared regions, but some services also perform runtime I/O, such as telemetry sockets, snapshot download and reads, and accounts DB file access.

Topology is defined in Zig, not ZON:

1. `init/services.zig` declares each service's `ReadOnly` and `ReadWrite` region schema.
2. `init/main.zig` declares the `Topology` type.
3. `init/main.zig` creates and initializes shared memory regions.
4. `init/main.zig` passes initialized regions to `children.spawn(...)`.

Changing the service graph requires changing `main.zig`. The runtime config file cannot select a different topology. `config/example.zon` shows how `Config` fields are set and loaded for the topology defined in `init/main.zig`.

Different "mains" (entry points) can be used to create integration tests on services in isolation with a different topology that allows for minimization of setup.

# Adding a New Service

This walkthrough adds a service called `foo` that reads a config region and logs through telemetry.

Start by defining the data layout that will live in shared memory. The struct must be `extern` so its layout is stable across process boundaries. Since regions are mapped at different virtual addresses in each process, pointer values from one process are invalid in another. Use fixed-size buffers with length fields instead of pointers or slices.

```zig
// lib/foo.zig
pub const Config = extern struct {
    bar_buf: [64]u8,
    bar_len: u8,
};
```

Register it in `lib/lib.zig` alongside the other modules:

```diff
 comptime {
     if (@import("builtin").is_test) {
         _ = @import("telemetry.zig");
+        _ = @import("foo.zig");
     }
 }

 pub const telemetry = @import("telemetry.zig");
+pub const foo = @import("foo.zig");
```

Declare the service schema in `init/services.zig`:

```zig
pub const foo: ServiceSpec = .{
    .ReadOnly = struct {
        config: *const lib.foo.Config,
    },
    .ReadWrite = struct {
        tel: *lib.telemetry.Region,
    },
};
```

Write the service in `services/foo.zig`:

```zig
const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");

comptime {
    _ = start;
}

pub const name = .foo;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.foo.ReadOnly;
pub const ReadWrite = services.foo.ReadWrite;

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    const bar = ro.config.bar_buf[0..ro.config.bar_len];
    logger.info().logf("foo service started with bar: {s}", .{bar});

    try runner.activity.signalIdleImmediate();
    while (true) : (std.atomic.spinLoopHint()) {
        try runner.activity.checkCanceled();
    }
}
```

Add runtime config fields in `init/main.zig` if the service needs operator controlled values:

```zig
const Config = struct {
    // existing fields...
    foo: Foo,

    const Foo = struct {
        bar: []const u8,
    };
};
```

Add the corresponding entry to your runtime config. If the field is required by `Config`, also update `config/example.zon` so the checked in example remains valid:

```zig
.foo = .{
    .bar = "hello from foo!",
},
```

Add the service to the `Topology` type in `init/main.zig`:

```zig
const Topology = struct {
    // existing services...
    foo: ServiceRegions(services.foo),
};
```

Create and initialize the shared memory region before the spawn block:

```zig
var foo_config: Region(lib.foo.Config) = try .simple();
const foo_data = foo_config.ptr();
@memcpy(foo_data.bar_buf[0..config.foo.bar.len], config.foo.bar);
foo_data.bar_len = @intCast(config.foo.bar.len);
```

Wire the service in the `children.spawn(...)` topology value:

```zig
.foo = .{
    .ro = .{ .config = foo_config.finish() },
    .rw = .{ .tel = telemetry_region.finish() },
},
```

The build discovers services from the public declarations in `init/services.zig`, so adding `pub const foo` there also makes `build.zig` compile and link `services/foo.zig`.
