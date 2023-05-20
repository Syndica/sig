<br/>

<p align="center">
  <h1>&nbsp;🤖  &nbsp;&nbsp;Sig - a Zig Solana RPC client</h1>
    <br/>
    <br/>
  <a href="https://github.com/syndica/sig/releases/latest"><img alt="Version" src="https://img.shields.io/github/v/release/syndica/sig?include_prereleases&label=version"></a>
  <a href="https://github.com/syndica/sig/actions/workflows/test.yml"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/syndica/sig/test.yml?branch=main" /></a>
  <a href="https://ziglang.org/download"><img alt="Zig" src="https://img.shields.io/badge/zig-master-green.svg"></a>
  <a href="https://github.com/syndica/sig/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>
<br/>

## Overview

_Sig_ is a Solana RPC client implementation written in Zig.
<br/>
<br/>

## Why Zig?

Zig's own definition: `Zig is a general-purpose programming language and toolchain for maintaining robust, optimal and reusable software.`

1. **Optimized performance**: Zig provides control over how your program runs at a low level, similar to languages like C or C++. It allows fine-grained control over aspects such as memory management and system calls, which can lead to improved performance.

2. **Safety focus**: Zig has features built in to prevent common bugs and safety issues. For example, it includes built-in testing and bounds checking, which can help avoid problems such as buffer overflows and undefined behavior.

3. **Readability and maintainability**: Zig syntax is designed to be straightforward and clear. This can make the code easier to understand, more maintainable, and less prone to bugs.

4. **No hidden control flow**: Zig doesn't allow hidden control-flow like exceptions in some other languages. This can make it easier to reason about what your program is doing.

5. **Integration with C**: Zig has excellent interoperation with C. You can directly include C libraries and headers in a Zig program, which can save time when using existing C libraries.

6. **Cross-compiling**: Zig has out-of-the-box support for cross-compilation, making it easy to compile your code for different platforms and architectures from a single system.

7. **Custom allocators**: Zig allows you to define custom memory allocation strategies for different parts of your program. This provides the flexibility to optimize memory usage for specific use-cases or workloads.

## Notes:

- Zig is still a evolving language.
- Many of the low-level APIs have been stabilized but `std.http.Client` and `std.json` are still WIP targetting stable implementations by `>=0.11`.
- This library was compiled and tested using `0.11.0-dev.3218+b873ce1e0` (master).
- Zig is targeting May 30th, 2023 for [`0.11` milestone](https://github.com/ziglang/zig/milestone/17).
- Currently, `std.http.Client` [leaks](https://github.com/ziglang/zig/blob/447a30299073ce88b7b26d18d060a345beac5276/lib/std/http/Client.zig#L913) and is failing some tests.
  <br/>
  <br/>

## Modules:

- **RPC Client** - A fully featured HTTP RPC client with ability to query all on-chain data along with sending transactions.

## Installation

Add `Sig` to your Zig project using `build.zig.zon` file (available for Zig >= 0.11).

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
   <br/>

### API Reference

<details>
<summary><code>getAccountInfo: (address: Pubkey, options: GetAccountInfoOptions)</code></summary>
<br/>
Returns all information associated with the account of provided Pubkey
<br/>
<br/>

**Options**
<br/>

```zig
const GetAccountInfoOptions = struct {
    commitment: ?types.Commitment = null,
    encoding: types.Encoding = .Base64,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const Pubkey = sig.Pubkey;
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    const pubkey = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");

    var resp = try client.getAccountInfo(pubkey, .{ .encoding = .Base64 });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("Account info: {any}", .{resp.result().value.data});
}
```

</details>

<details>
<summary><code>getBalance: (pubkey: Pubkey)</code></summary>
<br/>
Returns the balance of the account of provided Pubkey
<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const Pubkey = sig.Pubkey;
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    const pubkey = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");

    var resp = try client.getBalance(pubkey);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("balance info: {any}", .{resp.result().value});
}
```

</details>

<details>
<summary><code>getBlockHeight: ()</code></summary>
<br/>
Returns the current block height of the node
<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockHeight();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block height: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlock: (slot: u64, options: GetBlockOptions)</code></summary>
<br/>
Returns identity and transaction information about a confirmed block in the ledger
<br/>
<br/>

**Options**
<br/>

```zig
const GetBlockOptions = struct {
    commitment: ?types.Commitment = null,
    maxSupportedTransactionVersion: i64 = 0,
    transactionDetails: []const u8 = "full",
    rewards: bool = false,
    /// NOTE: must be json for now
    encoding: types.Encoding = .Json,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlock(500, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlockProduction: (options: GetBlockOptions)</code></summary>
<br/>
Returns recent block production information from the current or previous epoch.
<br/>
<br/>

**Options**
<br/>

```zig
const GetBlockProductionOptions = struct {
    commitment: ?types.Commitment = null,
    identity: ?[]const u8 = null,
    range: ?struct {
        firstSlot: u64,
        lastSlot: ?u64,
    } = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockProduction(.{ .identity = "1EWZm7aZYxfZHbyiELXtTgN1yT2vU1HF9d8DWswX2Tp" });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block production info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlockCommitment: (slot: u64)</code></summary>
<br/>
Returns commitment for particular block
<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockCommitment(400);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block commitment info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlocks: (startSlot: u64, endSlot: ?u64, options: GetBlocksOptions)</code></summary>
<br/>
Returns a list of confirmed blocks between two slots

<br/>
<br/>

**Options**
<br/>

```zig
const GetBlocksOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlocks(400, 500, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("blocks: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlocksWithLimit: (startSlot: u64, limit: ?u64, options: GetBlocksOptions)</code></summary>
<br/>
Returns a list of confirmed blocks starting at the given slot

<br/>
<br/>

**Options**
<br/>

```zig
const GetBlocksOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlocksWithLimit(400, 25, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("blocks: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlockTime: (slot: u64)</code></summary>
<br/>
Returns the estimated production time of a block.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockTime(163954396);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block time: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getClusterNodes: ()</code></summary>
<br/>
Returns information about all the nodes participating in the cluster

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getClusterNodes();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("cluster nodes: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getEpochInfo: (options: GetEpochInfoOptions)</code></summary>
<br/>
Returns information about the current epoch

<br/>
<br/>

**Options**
<br/>

```zig
const GetEpochInfoOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getEpochInfo(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("epoch info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getEpochSchedule: ()</code></summary>
<br/>
Returns the epoch schedule information from this cluster

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getEpochSchedule();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("epoch schedule: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getFeeForMessage: (message: []const u8, options: GetFeeForMessageOptions)</code></summary>
<br/>
Get the fee the network will charge for a particular Message

<br/>
<br/>

**Options**
<br/>

```zig
const GetFeeForMessageOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getFeeForMessage("AQABAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQAA", .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("message fee info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getFirstAvailableBlock: ()</code></summary>
<br/>
Returns the slot of the lowest confirmed block that has not been purged from the ledger

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getFirstAvailableBlock();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("first available block: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getGenesisHash: ()</code></summary>
<br/>
Returns the genesis hash.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var resp = try client.getGenesisHash();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("genesis hash: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getHealth: ()</code></summary>
<br/>
Returns the current health of the node.

NOTE: If one or more --known-validator arguments are provided to solana-validator - "ok" is returned when the node has within HEALTH_CHECK_SLOT_DISTANCE slots of the highest known validator, otherwise an error is returned. "ok" is always returned if no known validators are provided.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getHealth();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("health: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getHighestSnapshotSlot: ()</code></summary>
<br/>
Returns the highest slot information that the node has snapshots for.

This will find the highest full snapshot slot, and the highest incremental snapshot slot based on the full snapshot slot, if there is one.
<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getHighestSnapshotSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("snapshot info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getIdentity: ()</code></summary>
<br/>
Returns the identity pubkey for the current node.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getIdentity();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("indentity info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getInflationGovernor: (options: GetInflationGovernorOptions)</code></summary>
<br/>
Returns the current inflation governor.

<br/>
<br/>

**Options**
<br/>

```zig
const GetInflationGovernorOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getInflationGovernor(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("inflation info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getInflationRate: ()</code></summary>
<br/>
Returns the specific inflation values for the current epoch

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getInflationRate();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("inflation rate: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getInflationReward: (accounts: []Pubkey, options: GetInflationRewardOptions)</code></summary>
<br/>
Returns the inflation / staking reward for a list of addresses for an epoch.

<br/>
<br/>

**Options**
<br/>

```zig
const GetInflationRewardOptions = struct {
    commitment: ?types.Commitment = null,
    epoch: ?u64 = null,
    minContextSlot: ?u64 = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var accounts = [2]Pubkey{
        try Pubkey.fromString(
            "6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu",
        ) ,
        try Pubkey.fromString(
            "BGsqMegLpV6n6Ve146sSX2dTjUMj3M92HnU8BbNRMhF2",
        ),
    };
    var resp = try client.getInflationReward(&accounts, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("inflation reward info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getLargestAccounts: (options: GetLargestAccountsOptions)</code></summary>
<br/>
Returns the 20 largest accounts, by lamport balance (results may be cached up to two hours)

<br/>
<br/>

**Options**
<br/>

```zig
const GetLargestAccountsOptions = struct {
    commitment: ?types.Commitment = null,
    filter: ?enum { Circulating, NonCirculating } = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLargestAccounts(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("largest accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getLatestBlockhash: (options: GetLatestBlockhashOptions)</code></summary>
<br/>
Returns the latest blockhash.

<br/>
<br/>

**Options**
<br/>

```zig
const GetLatestBlockhashOptions = struct {
    commitment: ?types.Commitment = null,
    minContextSlot: ?u64 = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLatestBlockhash(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("latest blockhash: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getLeaderSchedule: (epoch: ?u64, options: GetLeaderScheduleOptions)</code></summary>
<br/>
Returns the leader schedule for an epoch.

<br/>
<br/>

**Options**
<br/>

```zig
const GetLeaderScheduleOptions = struct {
    commitment: ?types.Commitment = null,
    identity: ?[]const u8 = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLeaderSchedule(null, .{ .identity = "GRmtMtAeSL8HgX1p815ATQjaYU4Sk7XCP21i4yoFd3KS" });
    // defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("leader schedule: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getMaxRetransmitSlot: ()</code></summary>
<br/>
Get the max slot seen from retransmit stage.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMaxRetransmitSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("max retransmit slot: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getMaxShredInsertSlot: ()</code></summary>
<br/>
Get the max slot seen from after shred insert.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMaxShredInsertSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("max shred insert slot: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getMinimumBalanceForRentExemption: (size: usize)</code></summary>
<br/>
Returns minimum balance required to make account rent exempt.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMinimumBalanceForRentExemption(1000);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("minimum balance: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getMultipleAccounts: (pubkeys: []Pubkey, options: GetMultipleAccountsOptions)</code></summary>
<br/> 
Returns the account information for a list of Pubkeys.

<br/>
<br/>

**Options**
<br/>

```zig
const GetMultipleAccountsOptions = struct {
    commitment: ?types.Commitment = null,
    encoding: types.Encoding = .Base64,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var accounts2 = [2]Pubkey{
        try Pubkey.fromString(
            "4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa",
        ),
        try Pubkey.fromString(
            "BGsqMegLpV6n6Ve146sSX2dTjUMj3M92HnU8BbNRMhF2",
        ),
    };
    var resp = try client.getMultipleAccounts(&accounts2, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("multiple accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getProgramAccounts: (program: Pubkey, options: GetProgramAccountsOptions)</code></summary>
<br/> 
Returns all accounts owned by the provided program Pubkey.

<br/>
<br/>

**Options**
<br/>

```zig
pub const GetProgramAccountsOptions = struct {
    commitment: ?types.Commitment = null,
    /// NOTE: this needs to base64 if want to convert to `core.Account` type
    encoding: types.Encoding = .Base64,
    minContextSlot: ?u64 = null,
    /// NOTE: needs to be true
    withContext: bool = true,
    dataSlice: ?DataSlice = null,
    filters: ?[]Filter = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var filters = [1]Filter{.{ .memcmp = .{ .offset = 0, .bytes = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" } }};
    var resp = try client.getProgramAccounts(
        try Pubkey.fromString("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        .{ .filters = &filters },
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("program accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getRecentPerformanceSamples: (limit: ?u64)</code></summary>
<br/> 
Returns a list of recent performance samples, in reverse slot order. Performance samples are taken every 60 seconds and include the number of transactions and slots that occur in a given time window.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getRecentPerformanceSamples(null);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("recent performance samples: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getRecentPrioritizationFees: (pubkeys: ?[]Pubkey)</code></summary>
<br/> 
Returns a list of prioritization fees from recent blocks.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getRecentPrioritizationFees(null);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("recent prioritization fees: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getSignaturesForAddress: (pubkey: Pubkey, options: GetSignaturesForAddressOptions)</code></summary>
<br/> 
Returns signatures for confirmed transactions that include the given address in their accountKeys list. Returns signatures backwards in time from the provided signature or most recent confirmed block.

<br/>
<br/>

**Options**
<br/>

````zig
pub const GetSignaturesForAddressOptions = struct {
    commitment: ?types.Commitment = null,
    minContextSlot: ?u64 = null,
    limit: u32 = 1000,
    before: ?[]const u8 = null,
    until: ?[]const u8 = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSignaturesForAddress(try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa"), .{ .limit = 10 });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("signatures: {any}", .{resp.result()});
}
````

</details>

<details>
<summary><code>getSignatureStatuses: (pubkey: Pubkey, options: GetSignatureStatusesOptions)</code></summary>
<br/> 
Returns the statuses of a list of signatures. Each signature must be a txid, the first signature of a transaction.

<br/>
<br/>

**Options**
<br/>

```zig
const GetSignatureStatusesOptions = struct {
    searchTransactionHistory: bool = false,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var signatures = [2][]const u8{
        "3oK4vMqnRbLhdNVq9Cb81JwHim4QaxvgcNEyA4jTySFFtFtBhJgmLwT3rMFAGakKHE9iMiymVNZsTbnrzNjuxXJc",
        "5fqHdfeY1GbshDFzTdybqDbR3mwj5tkgHEP28dFWFZDcvQkkJUynVWrsfMYip8SsfAaFYTFmRdeC3K1CQRC7Ukkb",
    };
    var resp = try client.getSignatureStatuses(&signatures, .{ .searchTransactionHistory = true });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("signature statuses: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getSlotLeader: (options: GetSlotLeaderOptions)</code></summary>
<br/> 
Returns the current slot leader.

<br/>
<br/>

**Options**
<br/>

```zig
const GetSlotLeaderOptions = struct {
    commitment: ?types.Commitment = null,
    minContextSlot: ?u64 = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSlotLeader(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("slot leader: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getSlotLeaders: (startSlot: ?u64, limit: ?u64)</code></summary>
<br/> 
Returns the slot leaders for a given slot range.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSlotLeaders(193536000, 10);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("slot leaders: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getStakeActivation: (pubkey: Pubkey, options: GetStakeActivationOptions)</code></summary>
<br/> 
Returns epoch activation information for a stake account.

<br/>
<br/>

**Options**
<br/>

```zig
pub const GetStakeActivationOptions = struct {
    commitment: ?types.Commitment = null,
    minContextSlot: ?u64 = null,
    epoch: ?u64 = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getStakeActivation(try Pubkey.fromString(
        "CWrKSEDYhj6VHGocZowq2BUncKESqD7rdLTSrsoasTjU",
    ), .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("stake activation: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getStakeMinimumDelegation: (options: GetStakeMinimumDelegationOptions)</code></summary>
<br/> 
Returns epoch activation information for a stake account.

<br/>
<br/>

**Options**
<br/>

```zig
const GetStakeMinimumDelegationOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getStakeMinimumDelegation(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("min stake delegation: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getSupply: (options: GetSupplyOptions)</code></summary>
<br/> 
Returns information about the current supply.

<br/>
<br/>

**Options**
<br/>

```zig
const GetSupplyOptions = struct {
    commitment: ?types.Commitment = null,
    excludeNonCirculatingAccountsList: ?bool = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSupply(.{ .excludeNonCirculatingAccountsList = false });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("get supply: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenAccountBalance: (pubkey: Pubkey, options: GetTokenAccountBalanceOptions)</code></summary>
<br/> 
Returns the token balance of an SPL Token account.

<br/>
<br/>

**Options**
<br/>

```zig
const GetTokenAccountBalanceOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var pubkey = try Pubkey.fromString(
        "6A5NHCj1yF6urc9wZNe6Bcjj4LVszQNj5DwAWG97yzMu",
    );
    var resp = try client.getTokenAccountBalance(pubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token account balance: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenAccountsByDelegate: (pubkey: Pubkey, mintOrProgramId: MintOrProgramIdParam, options: GetTokenAccountsByDelegateOptions)</code></summary>
<br/> 
Returns all SPL Token accounts by approved Delegate.

<br/>
<br/>

**Options**
<br/>

```zig
const MintOrProgramIdParam = struct {
    mint: ?Pubkey = null,
    programId: ?Pubkey = null,
};

const GetTokenAccountsByDelegateOptions = struct {
    commitment: ?types.Commitment = null,
    encoding: types.Encoding = .Base64,
    minContextSlot: ?u64 = null,
    dataSlice: ?DataSlice = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var programPubkey = try Pubkey.fromString(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    );
    var pubkey = try Pubkey.fromString(
        "CTz5UMLQm2SRWHzQnU62Pi4yJqbNGjgRBHqqp6oDHfF7",
    );
    var resp = try client.getTokenAccountsByDelegate(pubkey, .{ .programId = programPubkey }, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenAccountsByOwner: (pubkey: Pubkey, mintOrProgramId: MintOrProgramIdParam, options: GetTokenAccountsByOwnerOptions)</code></summary>
<br/> 
Returns all SPL Token accounts by token owner.

<br/>
<br/>

**Options**
<br/>

```zig
const MintOrProgramIdParam = struct {
    mint: ?Pubkey = null,
    programId: ?Pubkey = null,
};

const GetTokenAccountsByOwnerOptions = struct {
    commitment: ?types.Commitment = null,
    encoding: types.Encoding = .Base64,
    minContextSlot: ?u64 = null,
    dataSlice: ?DataSlice = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.fromString(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var pubkey = try Pubkey.fromString(
        "CTz5UMLQm2SRWHzQnU62Pi4yJqbNGjgRBHqqp6oDHfF7",
    );
    var resp = try client.getTokenAccountsByOwner(pubkey, .{ .mint = mintPubkey }, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenLargestAccounts: (pubkey: Pubkey, options: GetTokenLargestAccountsOptions)</code></summary>
<br/> 
Returns the 20 largest accounts of a particular SPL Token type.

<br/>
<br/>

**Options**
<br/>

```zig
const GetTokenLargestAccountsOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.fromString(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var resp = try client.getTokenLargestAccounts(mintPubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token largest accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenSupply: (pubkey: Pubkey, options: GetTokenSupplyOptions)</code></summary>
<br/> 
Returns the total supply of an SPL Token type.

<br/>
<br/>

**Options**
<br/>

```zig
const GetTokenSupplyOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.fromString(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var resp = try client.getTokenSupply(mintPubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token supply: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTransaction: (signature: []const u8, options: GetTransactionOptions)</code></summary>
<br/> 
Returns transaction details for a confirmed transaction.

<br/>
<br/>

**Options**
<br/>

```zig
const GetTransactionOptions = struct {
    commitment: ?types.Commitment = null,
    maxSupportedTransactionVersion: u8 = 0,
    /// NOTE: must be Json for now
    encoding: types.Encoding = .Json,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var txSig = "5UfDuX7WXY18keiz9mZ6zKkY8JyNuLDFz2QycQcr7skRkgVaNmo6tgFbsePRrX5C6crvycJ2A3txSdGgjPHvPbTZ";
    var resp = try client.getTransaction(txSig, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("transaction: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTransactionCount: (options: GetTransactionOptions)</code></summary>
<br/> 
Returns the current Transaction count from the ledger.

<br/>
<br/>

**Options**
<br/>

```zig
const GetTransactionCountOptions = struct {
    commitment: ?types.Commitment = null,
    minContextSlot: ?u64 = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getTransactionCount(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("transaction count: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getVersion: ()</code></summary>
<br/> 
Returns the current Solana version running on the node.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getVersion();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("version: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getVoteAccounts: (options: GetVoteAccountsOptions)</code></summary>
<br/> 
Returns the account info and associated stake for all the voting accounts in the current bank.

<br/>
<br/>

**Options**
<br/>

```zig
const GetVoteAccountsOptions = struct {
    commitment: ?types.Commitment = null,
    votePubkey: ?Pubkey = null,
    keepUnstakedDelinquents: ?bool = false,
    delinquentSlotDistance: ?u64 = 0,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var votePubkey = try Pubkey.fromString(
        "CertusDeBmqN8ZawdkxK5kFGMwBXdudvWHYwtNgNhvLu",
    );
    var resp = try client.getVoteAccounts(.{ .votePubkey = votePubkey });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("vote accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>isBlockhashValid: (blockhash: []const u8, options: IsBlockhashValidOptions)</code></summary>
<br/> 
Returns whether a blockhash is still valid or not.

<br/>
<br/>

**Options**
<br/>

```zig
pub const IsBlockhashValidOptions = struct {
    commitment: ?types.Commitment = null,
    minContextSlot: ?u64 = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.isBlockhashValid("AaPs8sYJjnDLMMAADYj2fPyDyNzp9to9v4J6c5gevxpX", .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("blockhash valid: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>minimumLedgerSlot: ()</code></summary>
<br/> 
Returns the lowest slot that the node has information about in its ledger.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.minimumLedgerSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("minimum ledger slot: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>requestAirdrop: (pubkey: Pubkey, lamports: u64, options: RequestAirdropOptions)</code></summary>
<br/> 
Requests an airdrop of lamports to a Pubkey.

<br/>
<br/>

**Options**
<br/>

```zig
const RequestAirdropOptions = struct {
    commitment: ?types.Commitment = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var pubkey = try Pubkey.fromString(
        "Bvg7GuhqwNmV2JVyeZjhAcTPFqPktfmq25VBaZipozda",
    );
    var resp = try client.requestAirdrop(pubkey, 10000, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("airdrop result: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>sendTransaction: (encoded: []const u8)</code></summary>
<br/> 
Submits a signed transaction to the cluster for processing.

This method does not alter the transaction in any way; it relays the transaction created by clients to the node as-is.

If the node's rpc service receives the transaction, this method immediately succeeds, without waiting for any confirmations. A successful response from this method does not guarantee the transaction is processed or confirmed by the cluster.

While the rpc service will reasonably retry to submit it, the transaction could be rejected if transaction's recent_blockhash expires before it lands.

Use getSignatureStatuses to ensure a transaction is processed and confirmed.

Before submitting, the following preflight checks are performed:

The transaction signatures are verified
The transaction is simulated against the bank slot specified by the preflight commitment. On failure an error will be returned. Preflight checks may be disabled if desired. It is recommended to specify the same commitment and preflight commitment to avoid confusing behavior.
The returned signature is the first signature in the transaction, which is used to identify the transaction (transaction id). This identifier can be easily extracted from the transaction data before submission.

<br/>
<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.sendTransaction(
        "4hXTCkRzt9WyecNzV1XPgCDfGAZzQKNxLXgynz5QDuWWPSAZBZSHptvWRL3BjCvzUXRdKvHL2b7yGrRQcWyaqsaBCncVG7BFggS8w9snUts67BSh3EqKpXLUm5UMHfD7ZBe9GhARjbNQMLJ1QD3Spr6oMTBU6EhdB4RD8CP2xUxr2u3d6fos36PD98XS6oX8TQjLpsMwncs5DAMiD4nNnR8NBfyghGCWvCVifVwvA8B8TJxE1aiyiv2L429BCWfyzAme5sZW8rDb14NeCQHhZbtNqfXhcp2tAnaAT",
        .{},
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("tx signature: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>simulateTransaction: (encoded: []const u8, options: SimulateTransactionOptions)</code></summary>
<br/> 
Simulate sending a transaction.

<br/>
<br/>

**Options**
<br/>

```zig
const SimulateTransactionOptions = struct {
    commitment: ?types.Commitment = null,
    /// NOTE: must be base64 for now
    encoding: types.Encoding = .Base64,
    sigVerify: ?bool = null,
    replaceRecentBlockhash: ?[]const u8 = null,
    minContextSlot: ?u64 = null,
    accounts: ?struct {
        addresses: []Pubkey,
        /// NOTE: must be base64 for now
        encoding: types.Encoding = .Base64,
    } = null,
};
```

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const RpcClient = sig.RpcClient;

const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try RpcClient.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.simulateTransaction(
        "AdYOLBh+RlElmqIY08YZ4OvkWzmGz5ccQLKOENWccchuSluWO7ZTy6B4x/A/WJAFvSFfUhXEcG/PZajL5EmZBQMBAAEDb3Q4CUF/hTg/MgAsYv45KRoWu+9GafjMndSktv5KzQ3fydC+bF4RL7cMFn8iCnd9sKVJp3K3PwOxVZ3agBBUWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjkczsB8wv5yFAgAKUdvb4irHybi2IEEHJcAJrfdhMfgBAgIAAQwCAAAAgJaYAAAAAAA=",
        .{},
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("simulate tx info: {any}", .{resp.result()});
}
```

</details>
