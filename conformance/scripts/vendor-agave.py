#!/usr/bin/env python
"""
Clone agave into the conformance environment and configure solfuzz-agave to use it.
This is useful for debugging agave's behavior to diagnose conformance failures.
"""

import os
import tomllib
import subprocess


conformance_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
agave_url = "https://github.com/firedancer-io/agave"


def main():
    # identify solfuzz-agave's dependencies on agave
    cargo_toml = f"{conformance_dir}/env/solfuzz-agave/Cargo.toml"
    with open(cargo_toml, "rb") as f:
        config = tomllib.load(f)
    revs = set()
    for _, v in config["dependencies"].items():
        if isinstance(v, dict) and v.get("git") == agave_url:
            revs.add(v["rev"])
    assert len(revs) == 1, f"multiple revs found: {revs}"
    rev = revs.pop()

    # clone agave if not already present
    agave_dir = f"{conformance_dir}/env/agave"
    if not os.path.exists(agave_dir):
        result = subprocess.run(
            "git", "clone", f"--revision={rev}", "--depth=1", agave_url, agave_dir
        )
        assert result.returncode == 0, "failed to clone agave"

    # locate all agave crates
    agave_crate_to_path = {}
    for folder, _, files in os.walk(agave_dir):
        for file in files:
            if file == "Cargo.toml":
                with open(os.path.join(folder, file), "rb") as f:
                    crate = tomllib.load(f)
                if "package" in crate:
                    agave_crate_to_path[crate["package"]["name"]] = folder

    # replace git dependencies with path dependencies
    with open(cargo_toml, "r") as f:
        cargo_text = f.read()
    for crate, v in config["dependencies"].items():
        if isinstance(v, dict) and v.get("git") == agave_url:
            path = agave_crate_to_path[crate]
            cargo_text = cargo_text.replace(
                f'{crate} = {{git = "{agave_url}", rev = "{rev}"}}',
                f'{crate} = {{path = "{path}"}}',
            )
    with open(cargo_toml, "w") as f:
        f.write(cargo_text)


if __name__ == "__main__":
    main()
