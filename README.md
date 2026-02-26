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

## File Structure

```
src/
├─ sig.zig # library entrypoint
├─ cmd.zig # exec entrypoint
├─ tests.zig
├─ fuzz.zig
├─ benchmarks.zig
data/
├─ genesis-files/
├─ test-data/
docs/
metrics/
├─ prometheus/
├─ grafana/
├─ alloy/
├─ loki/
scripts/
```

## Resources

- [Official Website](https://www.syndica.io/sig)
- [Docs Page](https://sig.fun/)
- [Code Docs](https://syndica.github.io/sig/)
- [Discord](https://discord.gg/ucDSeZCmxH)
- [Engineering Blogposts](https://blog.syndica.io/tag/engineering/)
