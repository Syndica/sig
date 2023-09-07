# Contributing to Sig

Thank you for considering contributing to Syndica's Sig project! We appreciate your interest and support in helping us make this project better. By participating in this project, you are joining a community of developers and contributors working together to create value for the Solana ecosystem.

Before you start contributing, please take a moment to read and understand this Contributing Guidelines document. It will help you get started and ensure a smooth collaboration process.

## Writing Tests 
- when writing tests the naming convention is: `test "{path to file}: {test name}"`
  - for example, in `src/gossip/crds.zig` a test is defined as `test "gossip.crds: test CrdsValue label() and id() methods"`

## Linting
- run `zig fmt src/` in the top-level directory to run the zig linter