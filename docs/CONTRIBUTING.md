# Contributing to Sig
Thank you for considering contributing to Syndica's Sig project! We appreciate your interest and support in helping us make this project better.
By participating in this project, you are joining a community of developers and contributors working together to create value for the Solana ecosystem.
Before you start contributing, please take a moment to read and understand this Contributing Guidelines document. It will help you get started and ensure a smooth collaboration process.

## Dev Environment Setup
See the [readme](../readme.md#-setup).

## Style Guide

### Identifiers
To the extent that it is reasonable, we defer to the conventions established by the [Zig Style Guide](https://ziglang.org/documentation/master/#Style-Guide).

#### Constants
Non-function, constant declarations should be written in snake case with all letters uppercased (SCREAMING_SNAKE_CASE).
This includes constants which are intended to initialize an instance of a user type (ie which could be used as a decl literal).

#### Leading Underscores & Private Fields
Usage of leading underscores in identifiers, i.e (`_foo` or `__bar`) is discouraged unless it's in the correct contex.
Valid usages of such an identifier would be for a psuedo-private field, which is unrecommened for users to touch.
For private fields, there should be a docstring attached explaining that it's a private field. Before creating a private 
field, it should be considered whether it needs to be a field in the first place. There should be few usages of them.

#### Interfaces & Interface State
There are two main guidelines to keep in mind when naming interfaces and interface state:
- An instance of an interface should be named after the interface, unless the specific instance in question is expected to possess certain behaviours not prescribed by the intreface itself.
  - As an example, a generic instance of the `std.Random` interface should be named `random` - and for `std.mem.Allocator`, `allocator`.
  - As a contrasting example, if an instance of the `std.mem.Allocator` interface is expected to possess `arena`-like behaviour, it should be called `arena` or any other aptly-descriptive name.
- The name of the collective state of an interface should be derived from the name of the specific implementation, or from the behavior expected of the interface, in such a way that it is clearly
  denoted as being related to the instance of the interface it will represent.
  - As an example, a generic implementation of `std.Random` which is a pseudo-random number generator should be named `prng` (ie this is relevant when making appropriate use of `std.Random.DefaultPrng`).
  - As another example, an instance of `std.heap.GeneralPurposeAllocator(config)` should be called `gpa_state`, `std.heap.ArenaAllocator` `arena_state`, and so on.

#### Method Parameters
The first parameter of a method should be named `self`. The type should be the name of the struct. 
For example:

```zig
const MyStruct = struct {
    state: u8,

    fn write(self: *MyStruct, new_state: u8) void {
        self.state = new_state;
    }
};
```

If the type name is not available (for example in anonymous structs), define `const Self = @This()` 
and use that as the type.

### Files as Structs
We prohibit usage of files as instantiable struct types in the codebase.

### Imports 

#### Sig Dependencies
By convention, all internal dependencies should be defined as aliases of fully qualified paths from the root module.
For example, within 'src/gossip/message.zig' we should import types from 'src/gossip/data.zig' in the following manner:
```zig
const sig = @import("../sig.zig");

const GossipData = sig.gossip.data.GossipData;
```

#### Grouping
Group import statements and alias definitions into the following categories, separated by a newline:

1. @import statements
2. namespace aliases
3. struct aliases
4. function aliases
5. constant aliases

If it improves clarity, split groups into external and sig imports/aliases, otherwise list external imports/aliases before sig imports/aliases.
Within groups, try to follow alphabetical order with respect to fully qualified namespace i.e.
```zig
// Import statements
const std = @import("std");
const sig = @import("../sig.zig");

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
Optional values should be prepended with `maybe_`. For example:
```zig
fn do_something(maybe_foo: ?Foo) void {
    if (maybe_foo) |foo| {
        // do something with foo here
  }
}
```

### Function Signatures
- if passing an `Allocator` as a parameter, it should be the first parameter of the function, or the second if the function is intended as a method of the enclosing type.
- if the number of possible errors which a function can return is reasonably small (eg, can only fail on memory allocations), then the error types should be explicit (eg, `error{ OutOfMemory }`) instead of inferring the error set.
- if a parameter is not modified, then it should be `const` (eg, `fn get(*const Self)`)

### Slices
- when converting an array from a slice, the syntax `&buf` should be used instead of `buf[0..]`

### Writing Tests
- when writing tests the naming convention is: `test "{path to file}: {test name}"`
  - for example, in `src/gossip/data.zig` a test is defined as `test "gossip.data: test label() and id() methods"`

### Linting
- run `zig fmt src/` in the top-level directory to run the zig linter


### Metrics
It's common for a single context to deal with multiple prometheus metrics. In that case, it may be useful to group them together in their own struct. Any metrics structs following this pattern must end their names with the word `Metrics`. If practical, `Registry.initStruct` or `Registry.initFields` is recommended for the struct's initialization.

The name of the struct should be prefixed with a name describing the scope where it is used, as in `GossipMetrics`. The prefix may be omitted if the context is already obvious, and the following are true about the metrics struct:
- It is a private const.
- It is the only metrics struct defined in that context.
- It is expected to contain all metrics that would ever be used in any context where it the struct is accessible.
- The context's name would be redundantly expressed in its name. For example, shred_processor.zig encloses a metrics struct, for which the only sensible names would be ShredProcessorMetrics or Metrics. In this case, the context would be redundantly expressed, so it may be omitted.

If the Metrics struct is simple, and only used within one struct, it can be defined within that struct, otherwise it can be defined directly underneath the struct.
