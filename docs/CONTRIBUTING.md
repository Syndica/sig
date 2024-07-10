# Contributing to Sig

Thank you for considering contributing to Syndica's Sig project! We appreciate your interest and support in helping us make this project better. By participating in this project, you are joining a community of developers and contributors working together to create value for the Solana ecosystem.

Before you start contributing, please take a moment to read and understand this Contributing Guidelines document. It will help you get started and ensure a smooth collaboration process.

## Dev Environment Setup

See the [readme](../readme.md#-setup).

## Style Guide

### Imports 

#### Sig Dependencies
By convention, all internal dependencies should be defined as aliases of fully qualified paths from the root module. For example, within 'src/gossip/message.zig' we should import types from 'src/gossip/data.zig' in the following manner:
```zig
const sig = @import("../lib.zig");

const GossipData = sig.gossip.data.GossipData;
```

#### Grouping
Group import statements and alias definitions into the following categories, separated by a newline:

1. @import statements
2. namespace aliases
3. struct aliases
4. function aliases
5. constant aliases

If it improves clarity, split groups into external and sig imports/aliases, otherwise list external imports/aliases before sig imports/aliases. Within groups, try to follow alphabetical order with respect to fully qualified namespace i.e.
```zig
// Import statements
const std = @import("std");
const sig = @import("../lib.zig");

// Namespace aliases
const bincode = sig.bincode;
const pull_request = sig.gossip.pull_request;
const pull_response = sig.gossip.pull_response;

// External aliases
const EndPoint = network.EndPoint;
const UdpSocket = network.Socket;
const ArrayList = std.ArrayList;
const AtomicBool = std.atomic.Value(bool);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Thread = std.Thread;

// Sig aliases
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Entry = sig.trace.entry.Entry;
const Logger = sig.trace.log.Logger;
const EchoServer = sig.net.echo.Server;
const Packet = sig.net.Packet;
```

### Optional Values

- optional values should be prepended with `maybe_` and unwrapping should follow the `if (maybe_x) |x| {}` format
- for example:

```zig
fn do_something(maybe_foo: ?Foo) void {
    if (maybe_foo) |foo| {
        // do something with foo here
  }
}
```

### Function Signatures

- if passing an `Allocator` as a parameter, it should be the first parameter of the function
- if the number of possible errors which a function can return is reasonably small (eg, can only fail on memory allocations), then the error types should be explicit (eg, `error{ OutOfMemory }`) instead of using `anyerror` and the `!` operator
- if a parameter is not modified, then it should be `const` (eg, `fn get(*const Self)`)

### Slices

- when converting an array from a slice, the syntax `&buf` should be used instead of `buf[0..]`

### Writing Tests

- when writing tests the naming convention is: `test "{path to file}: {test name}"`
  - for example, in `src/gossip/data.zig` a test is defined as `test "gossip.data: test label() and id() methods"`

### Linting

- run `zig fmt src/` in the top-level directory to run the zig linter
