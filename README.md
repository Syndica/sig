<br/>

<p align="center">
  <h1 align="center">&nbsp;🤖⚡ &nbsp;<code>Sig</code> - a Solana validator client written in Zig</h1>
    <br/>
<div align="center">
  <a href="https://github.com/syndica/sig/releases/latest"><img alt="Version" src="https://img.shields.io/github/v/release/syndica/sig?include_prereleases&label=version"></a>
  <a href="https://ziglang.org/download"><img alt="Zig" src="https://img.shields.io/badge/zig-0.15.2-green.svg"></a>
  <a href="https://github.com/syndica/sig/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache_2.0-blue.svg"></a>
  <a href="https://dl.circleci.com/status-badge/redirect/gh/Syndica/sig/tree/main"><img alt="Build status" src="https://dl.circleci.com/status-badge/img/gh/Syndica/sig/tree/main.svg?style=svg" /></a>
  <a href="https://codecov.io/gh/Syndica/sig" >
  <img src="https://codecov.io/gh/Syndica/sig/graph/badge.svg?token=XGD0LHK04Y"/></a>
  </div>
</p>
<br/>

_Sig_ is a Solana validator client implemented in Zig. Read the [introductory blog post](https://blog.syndica.io/introducing-sig-by-syndica-an-rps-focused-solana-validator-client-written-in-zig/) for more about the goals of this project.
<br/>
<br/>

## Project Status

Sig currently ships as two implementations:

- **`v2/`**: The current implementation. `build.zig` in the repo root builds v2. A multi-process architecture where each service (gossip, shred receiver, snapshot, accountsdb, replay, exec, telemetry, net) runs in its own sandboxed process and communicates through typed shared-memory regions. New development happens here.
- **`v1/`**: The original single-process implementation. In maintenance mode: only critical bug fixes are accepted. Has its own `build.zig`.

Each implementation has an independent build process.

## File Structure

```
build.zig, build.zig.zon    # root build for v2
v2/                         # current multi-process implementation
v1/                         # original single-process implementation; maintenance mode
conformance/                # Solana/Firedancer test-vector harness; has its own build
config/                     # example v2 runtime config used by `zig build run`
data/                       # test fixtures used by v2 tests
docs/                       # docusaurus docs site and docs tooling
tools/                      # developer tools, CI, lint, docs, and v2 helpers
ci/run-and-update-service/  # continuous runner for deploying sig automatically
```

## Resources

- [Official Website](https://www.syndica.io/sig)
- [Docs Page](https://sig.fun/)
- [Code Docs](https://syndica.github.io/sig/)
- [Discord](https://discord.gg/ucDSeZCmxH)
- [Engineering Blogposts](https://blog.syndica.io/tag/engineering/)

## Build & Run

These instructions are for running Sig v2.

```sh
zig build                            # builds sig, tools, and all unit tests
zig build sig                        # builds only the sig binary
zig build run -- config/example.zon  # run sig
zig build ci                         # run all tests and validations
```

### Running a functional Sig validator

Sig v2 is not yet a complete validator, so there are some extra steps required to get the data it needs.

#### 1. Use Agave to create a leader schedule text file:

```sh
solana leader-schedule > schedule.txt
```

#### 2. Modify your config

`config/example.zon` shows the fields accepted by the runtime config and example values for running the current v2 topology. It is loaded as the `Config` type in `main.zig`. It controls values such as ports, cluster, telemetry settings, file paths, and memory sizes. It does not define service topology.

Point `leader_schedule_file` in your config at the leader schedule file.

#### 3. Start v2

```sh
zig build run -- config/example.zon
```

#### 4. Stream shreds into v2

v2 can receive shreds received over turbine, but it does not yet support repair, so it won't be able to the slots immediately after the snapshot. You can use the shred-stream tool to stream in a complete ledger. You'll need to collect the ledger from sig or agave, ensuring it has all slots starting at the snapshot slot being used by sig.

```
zig build shred-stream -- --ledger validator --target 127.0.0.1:8002 --rate-hz 100
```

### Running with Tracy

1. Build with `-Denable-tracy`.

2. Use `.sandboxing_mode = .threaded` in your runtime config (tracy requires a single address space).

### Linting
```sh
zig build lint
```

Pass explicit linter args after `--`:

```sh
zig build lint -- --fix  # automatically apply fixes
```

### Docs

```sh
zig build docs
python -m http.server -b 127.0.0.1 8000 -d zig-out/docs
```

### Tests

```sh
zig build unit-test  # all unit tests
zig build bb-test    # black-box integration tests
zig build test       # both
```

This runs all tests and validations of the entire v2 project, and is the process used for validations in CI:
```
zig build ci
```


## Detailed Directory Structure

```
.
├─ build.zig                 # root build for v2 binaries, tests, docs, and tools
├─ build.zig.zon             # root package manifest for v2
├─ config/
│   └─ example.zon           # example v2 runtime config
├─ tools/                    # repo-level developer tools
│   ├─ lint/                 # `zig build lint` implementation
│   ├─ shred_stream.zig      # `zig build shred-stream`
│   ├─ gen_docs_entry.zig    # docs build helper
│   ├─ fetch-zig-deps.py     # CI dependency prefetch helper
│   └─ ...                   # generators, coverage helpers, and misc scripts
├─ v1/                       # original single-process implementation
│   ├─ build.zig
│   ├─ build.zig.zon
│   ├─ scripts/              # v1-only benchmark, fuzz, gossip, and kcov scripts
│   └─ src/
├─ v2/                       # current multi-process implementation
│   ├─ main.zig              # root process: parses config, allocates regions, spawns services
│   ├─ services.zig          # ServiceSpec table for service ReadOnly/ReadWrite regions
│   ├─ services/             # service implementations
│   │   ├─ accounts_db.zig
│   │   ├─ exec.zig
│   │   ├─ gossip.zig
│   │   ├─ net.zig
│   │   ├─ replay.zig
│   │   ├─ shred_receiver.zig
│   │   ├─ snapshot.zig
│   │   └─ telemetry.zig
│   ├─ components/           # domain implementations, one subdir per component
│   │   ├─ accounts_db/      # each component has api.zig + component.zig + support files
│   │   ├─ gossip/
│   │   ├─ replay/
│   │   ├─ runtime/
│   │   ├─ shred/
│   │   └─ snapshot/
│   ├─ lib/                  # general-purpose primitives shared everywhere
│   │   ├─ lib.zig
│   │   ├─ account_pool.zig, clock.zig, collections.zig, crypto.zig, fio.zig,
│   │   ├─ ipc.zig, net.zig, runner.zig, solana.zig, telemetry.zig, time.zig, util.zig
│   │   └─ collections/, crypto/, fio/, ipc/, solana/, telemetry/
│   ├─ init/                 # topology setup and service entrypoint support
│   │   ├─ topology.zig      # Used in a topology's main file to initialize a topology.
│   │   ├─ start_service.zig # panic/log/signal glue linked into every service lib
│   │   └─ linux.zig         # Linux helpers for topology.zig
│   ├─ tests/                # integration tests that spin up partial topologies
│   │   └─ gossip/main.zig
│   └─ metrics/              # Grafana / Prometheus dashboards
├─ conformance/              # test-vector harness for v2 runtime and v1 compatibility code
│   ├─ build.zig
│   ├─ run.py
│   ├─ scripts/
│   └─ src/
├─ docs/                     # Docusaurus docs site
└─ ci/                       # deployment/runner support assets
```

## Code Categories

Every Zig file in v2 belongs to exactly one of these categories, and the module dependencies between categories are enforced by `build.zig`:

- **main files** (`main.zig`, `tests/**/main.zig`): Start up a full topology. Only main files may import `topology` and instantiate `Children`. Main files use `services.zig` to wire up regions and spawn the topology.
- **service implementations** (`services/*.zig`): One file per service, each built as a static library. A service runs in its own process and reads/writes only the regions declared for it in `services.zig`. Services import the components that they run, may import `lib`, any component `_api`, and the component impls they run. A service file is intended to be lightweight glue code that hooks up regions to components and orchestrates the component's execution in a single thread.
- **components** (`components/{name}/`): A high-level domain (e.g. gossip, accountsdb) that is implemented as a cohesive runnable unit. A component is directly imported and run by the service where it is used. Components do not invoke each other. Each has two modules:
  - `component`: The component itself. Only importable by services that declare them as dependencies. Imports `api` and any supporting files under the same directory.
  - `api`: Types used for interaction with the component by other components. visible to anyone (services, other components, main). May not import the sibling `component.zig`.
  - Other `*.zig` files in the component folder are supporting code used by `api` or `component`.
- **lib** (`lib/`): General-purpose primitives (ipc rings, Solana types, telemetry, IO helpers, crypto). Importable everywhere. `lib` may not depend on any component or service.
- **init** (`init/`): The general-purpose plumbing that turns a topology description into running processes.
  - `topology`: Used only by main files.
  - `start_service`: Linked into every service library because it exports the process entrypoint (`svc_main_<name>`).
- **tools** (`tools/`): Standalone developer utilities. Not part of any topology.

## Modules and Import Rules

`build.zig` creates the following named modules:

| module                 | source                                      | may be imported by                        |
| ---------------------- | ------------------------------------------- | ----------------------------------------- |
| `lib`                  | `lib/lib.zig`                               | anything                                  |
| `{component_name}_api` | `components/{component_name}/api.zig`       | services, main files, components          |
| `{component_name}`     | `components/{component_name}/component.zig` | only the services that run the component  |
| `topology`             | `init/topology.zig`                         | main files                                |
| `start_service`        | `init/start_service.zig`                    | service implementations                   |
| `services`             | `services.zig`                              | services, main files                      |
| `main`                 | `main.zig`                                  | not imported (root of the sig executable) |

Component apis do not import each other. This would be a code smell. Anything used by multiple APIs is likely a general-purpose validator concept, and should exist in `lib/` instead.

Services opt into a component impl by adding a `pub const components` decl in their `services.zig` entry. Services automatically have access to every API.

```zig
pub const replay = struct {
    pub const components = &.{"replay"}; // pulls in the `replay` module (components/replay/component.zig)
    pub const ReadOnly = struct { ... }; // can use the types from any API (purpose described below)
    pub const ReadWrite = struct { ... };
};
```

A service that doesn't declare `components` gets no component modules at all. Typically every service should use at least one component, unless it is a trivial component with no domain logic, such as the net service.

## Topology Internals

A topology describes a set of services that should run together and how they interact. The primary topology is Sig itself, but other topologies exist for testing.

Each service runs as an isolated process, or as a thread when `.sandboxing_mode = .threaded` (threaded mode is required for tracy). The runner (`main.zig`) orchestrates the creation of a full topology:

1. Define a `Topology` struct that lists which services to run.
2. Create shared-memory regions (typed via `Region(T)` from `init/topology.zig`) that will be used for inter-process communication between services.
3. Initialize each region's starting state.
4. Initialize the `Topology` struct, which wires the initialized regions into what each service will see as `ReadOnly` or `ReadWrite`.
5. Call `children.spawn(mode, topology)`, which forks each service, maps the requested regions into it, and installs a seccomp filter (sandboxed mode).
6. Monitor the children via `children.wait(...)` and shuts everything down on the first failure.

This process is implemented by `init/topology.zig`.

After spawning the child processes, the parent process monitors their health. See `lib/runner.zig` for the per-service health-tracking primitives (`Activity`, `Connection`).

Integration tests reuse this infrastructure with a smaller `Topology`. For example, `tests/gossip/main.zig` only spawns gossip and telemetry.

## Adding a New Component and Service

This walkthrough adds a component called `foo` and a service (also called `foo`) that runs it. The service reads a config region and logs through telemetry.

### 1. Create the component's api

`components/foo/api.zig` holds the types that other components will need to use in order to interact with this component. Anything shared through a memory region must be `extern`, since regions are mapped at different virtual addresses in each process (so pointer values from one process are invalid in another). A common pattern is to use a fixed-size buffer and share pointer offsets (array indexes) that let the reader recreate the pointer from its own base address.

```zig
// components/foo/api.zig
pub const Config = extern struct {
    bar_buf: [64]u8,
    bar_len: u8,

    pub fn bar(self: *const Config) []const u8 {
        return self.bar_buf[0..self.bar_len];
    }
};
```

`api.zig` may import `lib`, `tracy`, and `build-options`. It may not import its sibling `component.zig` or any other component.

### 2. Create the component impl

`components/foo/component.zig` is the component's implementation. It will typically be used directly by one service to implement a part of that service.

```zig
// components/foo/component.zig
pub const api = @import("api");
pub const Worker = struct {
    pub fn poll(self: *Worker) !void { ... }
};
```

You can also split the component or api implementation into multiple files in `components/foo/` and export the additional files in either `api.zig` or `component.zig` to make their code available publicly.

The build picks the new component up automatically on the next build. It iterates `components/` and creates two modules: `foo_api` (from `api.zig`) and `foo` (from `component.zig`).

### 3. Declare the service schema

Add a `foo` entry to `services.zig`:

```zig
const foo_api = @import("foo_api");

pub const foo = struct {
    pub const components = &.{"foo"};

    pub const ReadOnly = struct {
        config: *const foo_api.Config,
    };
    pub const ReadWrite = struct {
        tel: *lib.telemetry.Region,
    };
};
```

### 4. Write the service

`services/foo.zig` is the service impl. It runs as its own process (or thread) and only sees the regions declared in its `ReadOnly`/`ReadWrite`.

```zig
// services/foo.zig
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");
const foo_api = @import("foo_api");
const foo = @import("foo");

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

    var worker: foo.Worker = .init(ro.config);

    while (true) {
        if (!worker.poll(logger)) try runner.activity.signalIdleSpinning();
    }
}
```

The build discovers services from the public declarations in `services.zig`, so adding `pub const foo` there also makes `build.zig` compile and link `services/foo.zig`.

### 5. Wire the runtime config

Add operator-controlled fields to the `Config` struct in `main.zig` if the service needs any:

```zig
const Config = struct {
    // existing fields...
    foo: Foo,

    const Foo = struct {
        bar: []const u8,
    };
};
```

Add the corresponding entry to your runtime config. If the field is required by `Config`, also update `config/example.zon` so the checked-in example remains valid:

```zig
.foo = .{
    .bar = "hello from foo!",
},
```

### 6. Wire the topology

Add the service to the `Topology` type in `main.zig`:

```zig
const Topology = struct {
    // existing services...
    foo: ServiceRegions(.from(services.foo)),
};
```

Import the component api alongside the other `_api` imports at the top of `main.zig`:

```zig
const foo_api = @import("foo_api");
```

Create and initialize the shared memory region before the spawn block:

```zig
var foo_config: Region(foo_api.Config) = try .simple();
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
