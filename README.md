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

Sig currently ships as two parallel implementations:

- **`v2/`**: The current implementation. build.zig in the repo root is for v2. A multi-process architecture where each service (gossip, shred receiver, snapshot, accountsdb, replay, exec, telemetry, net) runs in its own sandboxed process and communicates through typed shared-memory regions. New development happens here. See [`v2/README.md`](v2/README.md) for architecture, build & run, and how to add a service or component.
- **`v1/`**: The original single-process implementation. In maintenance mode: only critical bug fixes are accepted. Has its own `build.zig`.

Each implementation has an independent build process.

## File Structure

```
build.zig, build.zig.zon    # top-level build for v2
README.md
v2/                         # current implementation (multi-process). See v2/README.md
v1/                         # original implementation (single-process, maintenance mode)
conformance/                # solana test-vector harness for v2 runtime, has its own build
config/                     # example runtime config for v2 (used by `zig build run`)
docs/                       # docusaurus docs site + generation scripts
scripts/                    # dev / ci scripts
ci/                 # supporting assets
```

## Resources

- [Official Website](https://www.syndica.io/sig)
- [Docs Page](https://sig.fun/)
- [Code Docs](https://syndica.github.io/sig/)
- [Discord](https://discord.gg/ucDSeZCmxH)
- [Engineering Blogposts](https://blog.syndica.io/tag/engineering/)
