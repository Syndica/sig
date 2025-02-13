---
sidebar_position: 5
title: Tests
---

Tests are defined at the bottom of each src file and referenced in `src/test.zig`.

Run all tests with the following command:

```bash
zig build test
```

Include a filter to limit which tests are run using `-Dfilter`.
For example, you can run all tests in `gossip.table` like this:

```bash
zig build test -Dfilter="gossip.table"
```

To see more information use the `--summary all` option:

```bash
zig build test -Dfilter="gossip.table" --summary all
```
