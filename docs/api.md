### `core.Pubkey` - API Reference

A struct which holds a Public Key of a Solana account (`[32]u8`).

<br/>

From a string:

```zig
const Pubkey = @import("sig").core.Pubkey;

fn main() !void {

    const pubkey = try Pubkey.parseBase58String("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");

}
```

<br/>

From raw bytes:

```zig
const Pubkey = @import("sig").core.Pubkey;

fn main() !void {

    // Automatically encodes and caches the string value
    const pubkey = try Pubkey.fromBytes(
        &[32]u8{
            44, 64, 232, 153, 35, 67, 7, 9, 46, 6, 87, 76, 55, 55, 65, 5,
            99, 0, 48, 64, 75, 8, 127, 53, 57, 12, 7, 54, 8, 133, 246, 4,
        },
        .{},
    );


    // Optionally skip encoding if (in the rare scenario) you will never call the string() method, you can
    // set this option to true and it will not decode & cache the encoded value. This can be helpful in
    // scenarios where you plan to only use the bytes and want to save on expensive base58 encoding.
    const pubkey = try Pubkey.fromBytes(
       &[32]u8{
            44, 64, 232, 153, 35, 67, 7, 9, 46, 6, 87, 76, 55, 55, 65, 5,
            99, 0, 48, 64, 75, 8, 127, 53, 57, 12, 7, 54, 8, 133, 246, 4,
        },
        .{ .skip_encoding = true },
    );

}
```

<br/>

### `rpc.Client` - API Reference

<br/>

A struct which allows you to interact with a Solana cluster via JSON RPC. You can instantiate a client like so:

```zig
const rpc = @import("sig").rpc;

const HTTP_ENDPOINT = "https://api.mainnet-beta.solana.com";

fn main() !void {
    var customHeaders = [_][2][]const u8{
        .{ "Cache-Control", "no-cache" },
        .{ "Authorization", "Bearer <SOME-TOKEN>" },
    };

    var client = try rpc.Client.init(allocator, .{
        .http_endpoint = HTTP_ENDPOINT,
        .http_headers = &customHeaders,
    });
    defer client.deinit();
}
```

<br/>
<br/>

<details>
<summary><code>getAccountInfo</code> - Returns all information associated with the account of provided Pubkey</summary>
<br/>

**Params:** <code>(address: Pubkey, options: GetAccountInfoOptions)</code>
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
const rpc = sig.rpc;
const Pubkey = sig.core.Pubkey;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    const pubkey = try Pubkey.parseBase58String("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");

    var resp = try client.getAccountInfo(pubkey, .{ .encoding = .Base64 });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("Account info: {any}", .{resp.result().value.data});
}
```

</details>

<details>
<summary><code>getBalance</code> - Returns the balance of the account of provided Pubkey</summary>
<br/>

**Params:** <code>(pubkey: Pubkey)</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;
const Pubkey = sig.core.Pubkey;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    const pubkey = try Pubkey.parseBase58String("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");

    var resp = try client.getBalance(pubkey);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("balance info: {any}", .{resp.result().value});
}
```

</details>

<details>
<summary><code>getBlockHeight</code> - Returns the current block height of the node</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockHeight();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("block height: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlock</code> - Returns identity and transaction information about a confirmed block in the ledger</summary>
<br/>

**Params:** <code>(slot: u64, options: GetBlockOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlock(500, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("block info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlockProduction</code> - Returns recent block production information from the current or previous epoch.</summary>
<br/>

**Params:** <code>(options: GetBlockOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockProduction(.{ .identity = "1EWZm7aZYxfZHbyiELXtTgN1yT2vU1HF9d8DWswX2Tp" });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("block production info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlockCommitment</code> - Returns commitment for particular block</summary>
<br/>

**Params:** <code>(slot: u64)</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockCommitment(400);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("block commitment info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlocks</code> - Returns a list of confirmed blocks between two slots.
</summary>
<br/>

**Params:** <code>(startSlot: u64, endSlot: ?u64, options: GetBlocksOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlocks(400, 500, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("blocks: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlocksWithLimit</code> - Returns a list of confirmed blocks starting at the given slot</summary>
<br/>

**Params:** <code>(startSlot: u64, limit: ?u64, options: GetBlocksOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlocksWithLimit(400, 25, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("blocks: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getBlockTime</code> - Returns the estimated production time of a block</summary>
<br/>

**Params:** <code>(slot: u64)</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockTime(163954396);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("block time: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getClusterNodes</code> - Returns information about all the nodes participating in the cluster</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getClusterNodes();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("cluster nodes: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getEpochInfo</code> - Returns information about the current epoch</summary>
<br/>

**Params:** <code>(options: GetEpochInfoOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getEpochInfo(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("epoch info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getEpochSchedule</code> - Returns the epoch schedule information from this cluster</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getEpochSchedule();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("epoch schedule: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getFeeForMessage</code> - Get the fee the network will charge for a particular Message</summary>
<br/>

**Params:** <code>(message: []const u8, options: GetFeeForMessageOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getFeeForMessage("AQABAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQAA", .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("message fee info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getFirstAvailableBlock</code> - Returns the slot of the lowest confirmed block that has not been purged from the ledger</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getFirstAvailableBlock();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("first available block: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getGenesisHash</code> - Returns the genesis hash</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var resp = try client.getGenesisHash();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("genesis hash: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getHealth</code> - Returns the current health of the node</summary>
<br/>

_NOTE:_ If one or more --known-validator arguments are provided to solana-validator - "ok" is returned when the node has within HEALTH_CHECK_SLOT_DISTANCE slots of the highest known validator, otherwise an error is returned. "ok" is always returned if no known validators are provided.

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getHealth();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("health: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getHighestSnapshotSlot</code> - Returns the highest slot information that the node has snapshots for</summary>
<br/>

_NOTE:_ This will find the highest full snapshot slot, and the highest incremental snapshot slot based on the full snapshot slot, if there is one.

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getHighestSnapshotSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("snapshot info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getIdentity</code> - Returns the identity pubkey for the current node</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getIdentity();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("indentity info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getInflationGovernor</code> - Returns the current inflation governor</summary>
<br/>

**Params:** <code>(options: GetInflationGovernorOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getInflationGovernor(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("inflation info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getInflationRate</code> - Returns the specific inflation values for the current epoch</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getInflationRate();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("inflation rate: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getInflationReward</code> - Returns the inflation / staking reward for a list of addresses for an epoch</summary>
<br/>

**Params:** <code>(accounts: []Pubkey, options: GetInflationRewardOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var accounts = [2]Pubkey{
        try Pubkey.parseBase58String(
            "6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu",
        ) ,
        try Pubkey.parseBase58String(
            "BGsqMegLpV6n6Ve146sSX2dTjUMj3M92HnU8BbNRMhF2",
        ),
    };
    var resp = try client.getInflationReward(&accounts, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("inflation reward info: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getLargestAccounts</code> - Returns the 20 largest accounts, by lamport balance (results may be cached up to two hours)</summary>
<br/>

**Params:** <code>(options: GetLargestAccountsOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLargestAccounts(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("largest accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getLatestBlockhash</code> - Returns the latest blockhash</summary>
<br/>
.

**Params:** <code>(options: GetLatestBlockhashOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLatestBlockhash(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("latest blockhash: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getLeaderSchedule</code> - Returns the leader schedule for an epoch</summary>
<br/>

**Params:** <code>(epoch: ?u64, options: GetLeaderScheduleOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLeaderSchedule(null, .{ .identity = "GRmtMtAeSL8HgX1p815ATQjaYU4Sk7XCP21i4yoFd3KS" });
    // defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("leader schedule: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getMaxRetransmitSlot</code> - Get the max slot seen from retransmit stage</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMaxRetransmitSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("max retransmit slot: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getMaxShredInsertSlot</code> - Get the max slot seen from after shred insert</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMaxShredInsertSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("max shred insert slot: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getMinimumBalanceForRentExemption</code> - Returns minimum balance required to make account rent exempt</summary>
<br/>

**Params:** <code>(size: usize)</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMinimumBalanceForRentExemption(1000);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("minimum balance: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getMultipleAccounts</code> - Returns the account information for a list of Pubkeys</summary>
<br/>

**Params:** <code>(pubkeys: []Pubkey, options: GetMultipleAccountsOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var accounts2 = [2]Pubkey{
        try Pubkey.parseBase58String(
            "4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa",
        ),
        try Pubkey.parseBase58String(
            "BGsqMegLpV6n6Ve146sSX2dTjUMj3M92HnU8BbNRMhF2",
        ),
    };
    var resp = try client.getMultipleAccounts(&accounts2, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("multiple accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getProgramAccounts</code> - Returns all accounts owned by the provided program Pubkey</summary>
<br/>

**Params:** <code>(pubkeys: []Pubkey, options: GetMultipleAccountsOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var filters = [1]Filter{.{ .memcmp = .{ .offset = 0, .bytes = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" } }};
    var resp = try client.getProgramAccounts(
        try Pubkey.parseBase58String("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        .{ .filters = &filters },
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("program accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getRecentPerformanceSamples</code> - Returns a list of recent performance samples, in reverse slot order</summary>
<br/>

_NOTE:_ Performance samples are taken every 60 seconds and include the number of transactions and slots that occur in a given time window.

**Params:** <code>(limit: ?u64)</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getRecentPerformanceSamples(null);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("recent performance samples: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getRecentPrioritizationFees</code> - Returns a list of prioritization fees from recent blocks</summary>
<br/>

**Params:** <code>(pubkeys: ?[]Pubkey)</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getRecentPrioritizationFees(null);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("recent prioritization fees: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getSignaturesForAddress</code> - Returns signatures for confirmed transactions that include the given address in their accountKeys list</summary>
<br/>

_NOTE:_ Returns signatures backwards in time from the provided signature or most recent confirmed block.

**Params:** <code>(pubkey: Pubkey, options: GetSignaturesForAddressOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSignaturesForAddress(try Pubkey.parseBase58String("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa"), .{ .limit = 10 });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("signatures: {any}", .{resp.result()});
}
````

</details>

<details>
<summary><code>getSignatureStatuses</code> - Returns the statuses of a list of signatures</summary>
<br/>

**Params:** <code>(pubkey: Pubkey, options: GetSignatureStatusesOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
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

    std.log.debugf("signature statuses: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getSlotLeader</code> - Returns the current slot leader</summary>
<br/>

**Params:** <code>(options: GetSlotLeaderOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSlotLeader(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("slot leader: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getSlotLeaders</code> - Returns the slot leaders for a given slot range</summary>
<br/>

**Params:** <code>(startSlot: ?u64, limit: ?u64)</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSlotLeaders(193536000, 10);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("slot leaders: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getStakeActivation</code> - Returns epoch activation information for a stake account</summary>
<br/>

**Params:** <code>(pubkey: Pubkey, options: GetStakeActivationOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getStakeActivation(try Pubkey.parseBase58String(
        "CWrKSEDYhj6VHGocZowq2BUncKESqD7rdLTSrsoasTjU",
    ), .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("stake activation: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getStakeMinimumDelegation</code> - Returns epoch activation information for a stake account</summary>
<br/>

**Params:** <code>(options: GetStakeMinimumDelegationOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getStakeMinimumDelegation(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("min stake delegation: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getSupply</code> - Returns information about the current supply</summary>
<br/>

**Params:** <code>(options: GetSupplyOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSupply(.{ .excludeNonCirculatingAccountsList = false });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("get supply: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenAccountBalance</code> - Returns the token balance of an SPL Token account</summary>
<br/>

**Params:** <code>(pubkey: Pubkey, options: GetTokenAccountBalanceOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var pubkey = try Pubkey.parseBase58String(
        "6A5NHCj1yF6urc9wZNe6Bcjj4LVszQNj5DwAWG97yzMu",
    );
    var resp = try client.getTokenAccountBalance(pubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("token account balance: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenAccountsByDelegate</code> - Returns all SPL Token accounts by approved Delegate</summary>
<br/>

**Params:** <code>(pubkey: Pubkey, mintOrProgramId: MintOrProgramIdParam, options: GetTokenAccountsByDelegateOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var programPubkey = try Pubkey.parseBase58String(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    );
    var pubkey = try Pubkey.parseBase58String(
        "CTz5UMLQm2SRWHzQnU62Pi4yJqbNGjgRBHqqp6oDHfF7",
    );
    var resp = try client.getTokenAccountsByDelegate(pubkey, .{ .programId = programPubkey }, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("token accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenAccountsByOwner</code> - Returns all SPL Token accounts by token owner</summary>
<br/>

**Params:** <code>(pubkey: Pubkey, mintOrProgramId: MintOrProgramIdParam, options: GetTokenAccountsByOwnerOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.parseBase58String(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var pubkey = try Pubkey.parseBase58String(
        "CTz5UMLQm2SRWHzQnU62Pi4yJqbNGjgRBHqqp6oDHfF7",
    );
    var resp = try client.getTokenAccountsByOwner(pubkey, .{ .mint = mintPubkey }, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("token accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenLargestAccounts</code> - Returns the 20 largest accounts of a particular SPL Token type</summary>
<br/>

**Params:** <code>(pubkey: Pubkey, options: GetTokenLargestAccountsOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.parseBase58String(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var resp = try client.getTokenLargestAccounts(mintPubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("token largest accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTokenSupply</code> - Returns the total supply of an SPL Token type</summary>
<br/>

**Params:** <code>(pubkey: Pubkey, options: GetTokenSupplyOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.parseBase58String(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var resp = try client.getTokenSupply(mintPubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("token supply: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTransaction</code> - Returns transaction details for a confirmed transaction</summary>
<br/>

**Params:** <code>(signature: []const u8, options: GetTransactionOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var txSig = "5UfDuX7WXY18keiz9mZ6zKkY8JyNuLDFz2QycQcr7skRkgVaNmo6tgFbsePRrX5C6crvycJ2A3txSdGgjPHvPbTZ";
    var resp = try client.getTransaction(txSig, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("transaction: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getTransactionCount</code> - Returns the current Transaction count from the ledger</summary>
<br/>

**Params:** <code>(options: GetTransactionOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getTransactionCount(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("transaction count: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getVersion</code> - Returns the current Solana version running on the node</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getVersion();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("version: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>getVoteAccounts</code> - Returns the account info and associated stake for all the voting accounts in the current bank</summary>
<br/>

**Params:** <code>(options: GetVoteAccountsOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var votePubkey = try Pubkey.parseBase58String(
        "CertusDeBmqN8ZawdkxK5kFGMwBXdudvWHYwtNgNhvLu",
    );
    var resp = try client.getVoteAccounts(.{ .votePubkey = votePubkey });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("vote accounts: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>isBlockhashValid</code> - Returns whether a blockhash is still valid or not</summary>
<br/>

**Params:** <code>(blockhash: []const u8, options: IsBlockhashValidOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.isBlockhashValid("AaPs8sYJjnDLMMAADYj2fPyDyNzp9to9v4J6c5gevxpX", .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("blockhash valid: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>minimumLedgerSlot</code> - Returns the lowest slot that the node has information about in its ledger</summary>
<br/>

**Params:** <code>None</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.minimumLedgerSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("minimum ledger slot: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>requestAirdrop</code> - Requests an airdrop of lamports to a Pubkey</summary>
<br/>

**Params:** <code>(pubkey: Pubkey, lamports: u64, options: RequestAirdropOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var pubkey = try Pubkey.parseBase58String(
        "Bvg7GuhqwNmV2JVyeZjhAcTPFqPktfmq25VBaZipozda",
    );
    var resp = try client.requestAirdrop(pubkey, 10000, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debugf("airdrop result: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>sendTransaction</code> - Submits a signed transaction to the cluster for processing</summary>
<br/>

_NOTE:_
This method does not alter the transaction in any way; it relays the transaction created by clients to the node as-is.

If the node's rpc service receives the transaction, this method immediately succeeds, without waiting for any confirmations. A successful response from this method does not guarantee the transaction is processed or confirmed by the cluster.

While the rpc service will reasonably retry to submit it, the transaction could be rejected if transaction's recent_blockhash expires before it lands.

Use getSignatureStatuses to ensure a transaction is processed and confirmed.

Before submitting, the following preflight checks are performed:

The transaction signatures are verified
The transaction is simulated against the bank slot specified by the preflight commitment. On failure an error will be returned. Preflight checks may be disabled if desired. It is recommended to specify the same commitment and preflight commitment to avoid confusing behavior.
The returned signature is the first signature in the transaction, which is used to identify the transaction (transaction id). This identifier can be easily extracted from the transaction data before submission.

**Params:** <code>(encoded: []const u8)</code>

<br/>

**Usage**
<br/>

```zig
const std = @import("std");
const sig = @import("sig");
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
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

    std.log.debugf("tx signature: {any}", .{resp.result()});
}
```

</details>

<details>
<summary><code>simulateTransaction</code> - Simulate sending a transaction</summary>
<br/>

**Params:** <code>(encoded: []const u8, options: SimulateTransactionOptions)</code>

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
const rpc = sig.rpc;


const allocator = std.heap.page_allocator;

pub fn main() !void {
    var client = try rpc.Client.init(allocator, .{ .http_endpoint = HTTP_ENDPOINT });
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

    std.log.debugf("simulate tx info: {any}", .{resp.result()});
}
```

</details>
