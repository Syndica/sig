# Contributing to Sig

Thank you for considering contributing to Syndica's Sig project! We appreciate your interest and support in helping us make this project better. By participating in this project, you are joining a community of developers and contributors working together to create value for the Solana ecosystem.

Before you start contributing, please take a moment to read and understand this Contributing Guidelines document. It will help you get started and ensure a smooth collaboration process.

## Debugger setup in VSCode

`tasks.json`:
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "build",
            "type": "shell",
            "command": "zig build",
            "problemMatcher": [],
            "group": {
                "kind": "build",
                "isDefault": true
            }
        }
    ]
}
```

`launch.json`:
```json
{
    "configurations": [
        {
            "name": "(lldb) Launch",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceRoot}/zig-out/bin/sig",
            "args": ["gossip","-e","86.109.15.59:8001"],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "lldb",
            "preLaunchTask": "build"
        }
    ],
    
}
```

## Style Guide

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
  - for example, in `src/gossip/crds.zig` a test is defined as `test "gossip.crds: test CrdsValue label() and id() methods"`

### Linting
- run `zig fmt src/` in the top-level directory to run the zig linter