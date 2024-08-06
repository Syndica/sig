<br/>

<p align="center">
  <h1 align="center">&nbsp;🤖⚡ &nbsp;<code>Sig</code> - a Solana Zig validator client</h1>
    <br/>
<div align="center">
  <a href="https://github.com/syndica/sig/releases/latest"><img alt="Version" src="https://img.shields.io/github/v/release/syndica/sig?include_prereleases&label=version"></a>
  <a href="https://github.com/syndica/sig/actions/workflows/check.yml"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/syndica/sig/check.yml?branch=main" /></a>
  <a href="https://ziglang.org/download"><img alt="Zig" src="https://img.shields.io/badge/zig-0.13.0-green.svg"></a>
  <a href="https://github.com/syndica/sig/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache_2.0-blue.svg"></a>
  </div>
</p>
<br/>

_Sig_ is a Solana validator client implemented in Zig. Read the [introductory blog post](https://blog.syndica.io/introducing-sig-by-syndica-an-rps-focused-solana-validator-client-written-in-zig/) for more about the goals of this project.
<br/>
<br/>

⚠️ NOTE: This is a WIP, please open any issues for any bugs/improvements.

## 📋 Setup

### Build Dependencies

- Zig 0.13.0 - Choose one:
  - [Binary Releases](https://ziglang.org/download/) (extract and add to PATH)
  - [Install with a package manager](https://github.com/ziglang/zig/wiki/Install-Zig-from-a-Package-Manager)
  - Manage multiple versions with [zigup](https://github.com/marler8997/zigup) or [zvm](https://www.zvm.app/)

<details><summary>

### Developer Tools</summary>

These tools are optional but recommended for a smooth development process.

- [Zig Language Server (ZLS) 0.13.0](https://github.com/zigtools/zls/wiki/Installation)
- [lldb](https://lldb.llvm.org/): [Zig CLI Debugging](https://devlog.hexops.com/2022/debugging-undefined-behavior/)
- [Zig Language](https://marketplace.visualstudio.com/items?itemName=ziglang.vscode-zig) VS Code extension
- [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) VS Code extension

#### Visual Studio Code

If you use VS Code, you should install the [Zig Language](https://marketplace.visualstudio.com/items?itemName=ziglang.vscode-zig) extension. It can use your installed versions of Zig and ZLS, or it can download and manage its own internal versions.

You can use [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) to debug Zig code with lldb in VS Code's debugging GUI. If you'd like to automatically build the project before running the debugger, you'll need a `zig build` task.

<details><summary>tasks.json</summary>

```yaml
{ ? // See https://go.microsoft.com/fwlink/?LinkId=733558
    // for the documentation about the tasks.json format
    "version"
  : "2.0.0", "tasks": [{ "label": "zig build", "type": "shell", "command": "zig", "args": ["build", "--summary", "all"], "options": { "cwd": "${workspaceRoot}" }, "presentation": { "echo": true, "reveal": "always", "focus": false, "panel": "shared", "showReuseMessage": true, "clear": false }, "problemMatcher": [], "group": { "kind": "build", "isDefault": true } }] }
```

</details>

To run the debugger, you need a run configuration. This launch.json includes an example for debugging gossip. Customize the args as desired.

<details><summary>launch.json</summary>

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug Gossip Mainnet",
      "program": "${workspaceFolder}/zig-out/bin/sig",
      "args": [
        "gossip",
        "--entrypoint",
        "entrypoint.mainnet-beta.solana.com:8001",
        "--entrypoint",
        "entrypoint2.mainnet-beta.solana.com:8001",
        "--entrypoint",
        "entrypoint3.mainnet-beta.solana.com:8001",
        "--entrypoint",
        "entrypoint4.mainnet-beta.solana.com:8001",
        "--entrypoint",
        "entrypoint5.mainnet-beta.solana.com:8001"
      ],
      "cwd": "${workspaceFolder}",
      "preLaunchTask": "zig build"
    }
  ]
}
```

</details>

</details>

## 🔧 Build

```bash
zig build
```

## 🚀 Run

Run Sig with `zig` or execute the binary you already built:

```bash
zig build run -- --help
```

```bash
./zig-out/bin/sig --help
```

These commands will be abbreviated as `sig` in the rest of this document.

### 👤 Identity

Sig stores its private key in `~/.sig/identity.key`. On its first run, Sig will automatically generate a key if no key exists. To see the public key, use the `identity` subcommand.

```bash
sig identity
```

### 📞 Gossip

To run Sig as a Solana gossip client, use the `gossip` subcommand. Specify entrypoints to connect to a cluster. Optionally use `-p` to specify a custom listening port (default is 8001). For more info about gossip, see the [readme](src/gossip/readme.md).

```bash
sig gossip -p <PORT> --entrypoint <IP>:<PORT>
```

The following IP addresses were resolved from domains found at https://docs.solana.com/clusters.

<details><summary>mainnet</summary>

```bash
sig gossip --entrypoint entrypoint.mainnet-beta.solana.com:8001 \
    --entrypoint entrypoint2.mainnet-beta.solana.com:8001 \
    --entrypoint entrypoint3.mainnet-beta.solana.com:8001 \
    --entrypoint entrypoint4.mainnet-beta.solana.com:8001 \
    --entrypoint entrypoint5.mainnet-beta.solana.com:8001
```

</details>

<details><summary>devnet</summary>

```bash
sig gossip --entrypoint entrypoint.devnet.solana.com:8001 \
    --entrypoint entrypoint2.devnet.solana.com:8001 \
    --entrypoint entrypoint3.devnet.solana.com:8001 \
    --entrypoint entrypoint4.devnet.solana.com:8001 \
    --entrypoint entrypoint5.devnet.solana.com:8001
```

</details>

<details><summary>testnet</summary>

```bash
sig gossip --entrypoint entrypoint.testnet.solana.com:8001 \
    --entrypoint entrypoint2.testnet.solana.com:8001 \
    --entrypoint entrypoint3.testnet.solana.com:8001
```

</details><br>

## Develop

See [Setup](#-setup) to get your environment set up. See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for the code style guide.

### 🧪 Test

Run all tests.

```bash
zig build test
```

Include `--summary all` with any test command to see a summary of the test results.

Include a filter to limit which tests are run. Sig tests include their module name. For example, you can run all tests in `gossip.table` like this:

```bash
zig build test --summary all -- gossip.table
```

### 📊 Benchmark

Run all benchmarks.

```bash
zig build benchmark
```

Run a benchmark group: socket_utils, gossip, or sync.

```bash
zig build benchmark -- gossip
```

<br>

## 📦 Import Sig

Sig can be included as a dependency in your Zig project using `build.zig.zon` file (available for Zig >= 0.12). See the [API documentation](docs/api.md) to learn more about how to use Sig as a library.

<details>
<summary><code>Steps</code> - how to install Sig in your Zig project</summary>

1. Declare Sig as a dependency in `build.zig.zon`:

   ```diff
   .{
       .name = "my-project",
       .version = "1.0.0",
       .dependencies = .{
   +       .sig = .{
   +           .url = "https://github.com/syndica/sig/archive/<COMMIT>.tar.gz",
   +       },
       },
   }
   ```

2. Expose Sig as a module in `build.zig`:

   ```diff
   const std = @import("std");

   pub fn build(b: *std.Build) void {
       const target = b.standardTargetOptions(.{});
       const optimize = b.standardOptimizeOption(.{});

   +   const opts = .{ .target = target, .optimize = optimize };
   +   const sig_module = b.dependency("sig", opts).module("sig");

       const exe = b.addExecutable(.{
           .name = "test",
           .root_source_file = .{ .path = "src/main.zig" },
           .target = target,
           .optimize = optimize,
       });
   +   exe.addModule("sig", sig_module);
       exe.install();

       ...
   }
   ```

3. Obtain Sig's package hash:

   ```
   $ zig build
   my-project/build.zig.zon:6:20: error: url field is missing corresponding hash field
           .url = "https://github.com/syndica/sig/archive/<COMMIT>.tar.gz",
                  ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   note: expected .hash = "<HASH>",
   ```

4. Update `build.zig.zon` with hash value:

   ```diff
   .{
       .name = "my-project",
       .version = "1.0.0",
       .dependencies = .{
           .sig = .{
               .url = "https://github.com/syndica/sig/archive/<COMMIT>.tar.gz",
   +           .hash = "<HASH>",
           },
       },
   }
   ```

      </details>
   <br>

## 🤔 Why Zig?

Zig's own definition: `Zig is a general-purpose programming language and toolchain for maintaining robust, optimal and reusable software.`

1. **Optimized performance**: Zig provides control over how your program runs at a low level, similar to languages like C. It allows fine-grained control over aspects such as memory management and system calls, which can lead to improved performance.

2. **Safety focus**: Zig has features built in to prevent common bugs and safety issues common in C. For example, it includes built-in testing and bounds checking, which can help avoid problems such as buffer overflows and undefined behavior.

3. **Readability and maintainability**: Zig syntax is designed to be straightforward and clear. This can make the code easier to understand, more maintainable, and less prone to bugs.

4. **No hidden control flow**: Zig doesn't allow hidden control-flow like exceptions in some other languages. This can make it easier to reason about what your program is doing.

5. **Integration with C**: Zig has excellent interoperation with C. You can directly include C libraries and headers in a Zig program, which can save time when using existing C libraries.

6. **Custom allocators**: Zig allows you to define custom memory allocation strategies for different parts of your program. This provides the flexibility to optimize memory usage for specific use-cases or workloads.

### Note

- Zig is still an evolving language.
- Many of the low-level APIs have been stabilized but `std.http.Client` and `std.json` are still WIP targetting stable implementations by `>=0.12`.
- Currently, `std.http.Client` [leaks](https://github.com/ziglang/zig/blob/447a30299073ce88b7b26d18d060a345beac5276/lib/std/http/Client.zig#L913) and is failing some tests, fix is in works.
  <br><br>

## 🧩 Modules

- **[Gossip](src/gossip)** - A gossip spy node, run by: `sig gossip` or `zig build run -- gossip`

- **[Core](src/core)** - Core data structures shared across modules.

- **[RPC Client](src/rpc)** ([docs](docs/api.md#rpcclient---api-reference)) - A fully featured HTTP RPC client with ability to query all on-chain data along with sending transactions.
  <br><br>

## 📚 Learn More

[Zig](https://ziglang.org/)

- [Official Documentation](https://ziglang.org/documentation/0.12.0/)
- [Ziglearn Book](https://ziglearn.org/)
- [Ziglings Exercises](https://github.com/ratfactor/ziglings)

[Solana](https://solana.com/)

- [Validator Anatomy](https://docs.solana.com/validator/anatomy)
- [RPC API](https://docs.solana.com/api)
- [Code](https://github.com/solana-labs/solana)

Sig

- [Introduction](https://blog.syndica.io/introducing-sig-by-syndica-an-rps-focused-solana-validator-client-written-in-zig/)
- [Gossip Deep Dive](https://blog.syndica.io/sig-engineering-1-gossip-protocol/)
