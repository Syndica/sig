#!/usr/bin/env bash
set -euo pipefail

# This script is a basic sanity check that the commit hashes in commits.env are
# consistent with our CI configuration. It's not perfect but checks for some
# obvious inconsistencies.

trap 'echo ❌ Failed to verify conformance commit at $LINENO: $BASH_COMMAND' ERR

# ensure working directory is repository root
cd $(dirname "${BASH_SOURCE[0]}")/../..

. conformance/commits.env

grep "// current commit: $SIG_PROTOSOL_COMMIT" conformance/build.zig > /dev/null

echo ✅  Verified conformance commits.
