---
sidebar_position: 1
title: Debugging
---

## General Tools

These tools are optional but recommended for a smooth development process.

- [Zig Language Server (ZLS) 0.11.0](https://github.com/zigtools/zls/wiki/Installation)
- [lldb](https://lldb.llvm.org/): [Zig CLI Debugging](https://devlog.hexops.com/2022/debugging-undefined-behavior/)
- [Zig Language](https://marketplace.visualstudio.com/items?itemName=ziglang.vscode-zig) VS Code extension
- [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) VS Code extension

## Visual Studio Code

### Setting up Debug Tasks

If you use VS Code, you should install the [Zig Language](https://marketplace.visualstudio.com/items?itemName=ziglang.vscode-zig) extension. It can use your installed versions of Zig and ZLS, or it can download and manage its own internal versions.

You can use [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) to debug Zig code with lldb in VS Code's debugging GUI. If you'd like to automatically build the project before running the debugger, you'll need a `zig build` task.

```json
{
    "version": "2.0.0",
    "tasks": [{
        "label": "zig build",
        "type": "shell",
        "command": "zig",
        "args": ["build", "--summary", "all"],
        "options": { "cwd": "${workspaceRoot}" },
        "presentation": { "echo": true, "reveal": "always", "focus": false, "panel": "shared", "showReuseMessage": true, "clear": false },
        "problemMatcher": [],
        "group": { "kind": "build", "isDefault": true }
    }]
}
```

To run the debugger, you need a run configuration. This launch.json includes an example for debugging gossip. Customize the args as desired.

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
        "--network",
        "mainnet"
      ],
      "cwd": "${workspaceFolder}",
      "preLaunchTask": "zig build"
    }
  ]
}
```
