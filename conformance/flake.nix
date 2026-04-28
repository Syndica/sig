{
  description = "Sig Conformance Testing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    zig-overlay,
    rust-overlay,
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [rust-overlay.overlays.default zig-overlay.overlays.default];
    };
    baseDeps = with pkgs; [zigpkgs."0.15.2" python313 git alejandra cargo rustc];
    commits = builtins.fromTOML (builtins.readFile ./commits.env);

    test-vectors = builtins.fetchGit {
      url = "https://github.com/firedancer-io/test-vectors.git";
      rev = commits.TEST_VECTORS_COMMIT;
    };
    solfuzz-agave = builtins.fetchGit {
      url = "https://github.com/firedancer-io/solfuzz-agave.git";
      rev = commits.SOLFUZZ_AGAVE_COMMIT;
    };
    solfuzz-agave-cargo-lock = builtins.fromTOML (builtins.readFile "${solfuzz-agave}/Cargo.lock");
    findLockedPackageSource = name: let
      matches = builtins.filter (pkg: pkg.name == name && pkg ? source) solfuzz-agave-cargo-lock.package;
    in
      if matches == [] then
        throw "Could not find ${name} in solfuzz-agave Cargo.lock"
      else
        (builtins.head matches).source;
    lockedGitRev = source: let
      parts = pkgs.lib.splitString "#" source;
    in
      if builtins.length parts < 2 then
        throw "Could not extract locked git revision from ${source}"
      else
        pkgs.lib.last parts;
    agave-locked-rev = lockedGitRev (findLockedPackageSource "agave-feature-set");
    sbpf-locked-rev = lockedGitRev (findLockedPackageSource "solana-sbpf");
    protosol = builtins.fetchGit {
      url = "https://github.com/firedancer-io/protosol.git";
      rev = commits.SOLFUZZ_AGAVE_PROTOSOL_COMMIT;
      submodules = true;
    };
    agave = builtins.fetchGit {
      url = "https://github.com/firedancer-io/agave.git";
      rev = agave-locked-rev;
    };
    sbpf = builtins.fetchGit {
      url = "https://github.com/firedancer-io/sbpf.git";
      rev = sbpf-locked-rev;
    };

    # protoc and flatc need to be the exact versions built by protosol
    protosol-toolchain = pkgs.stdenvNoCC.mkDerivation {
      pname = "protosol-toolchain";
      version = commits.SOLFUZZ_AGAVE_PROTOSOL_COMMIT;
      src = protosol;
      nativeBuildInputs = with pkgs; [ cmake gcc git pkg-config ];
      buildInputs = with pkgs; [ abseil-cpp zlib ];
      dontConfigure = true;
      buildPhase = ''
        patchShebangs ./deps.sh
        ./deps.sh
      '';
      installPhase = ''
        mkdir -p "$out"
        cp -r opt/bin/* "$out"
      '';
    };

    baseShellHook = ''
      export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [pkgs.stdenv.cc.cc.lib]}"
      mkdir -p env
      ln -sfn ${test-vectors} env/test-vectors

      python3.13 -m venv env/venv
      source env/venv/bin/activate
      ln -sfn "$PWD/run.py" env/venv/bin/run
      solana_conformance_install_root="$PWD/env/solana-conformance-install"
      if { [ -n "''${SOLANA_CONFORMANCE_REPO_URL:-}" ] && [ -z "''${SOLANA_CONFORMANCE_REF:-}" ]; } || { [ -z "''${SOLANA_CONFORMANCE_REPO_URL:-}" ] && [ -n "''${SOLANA_CONFORMANCE_REF:-}" ]; }; then
        echo "ERROR: SOLANA_CONFORMANCE_REPO_URL and SOLANA_CONFORMANCE_REF must both be set together."
        exit 1
      fi

      if [ -n "''${SOLANA_CONFORMANCE_REPO_URL:-}" ] && [ -n "''${SOLANA_CONFORMANCE_REF:-}" ]; then
        echo "SOLANA_CONFORMANCE_REPO_URL/SOLANA_CONFORMANCE_REF provided; cloning pinned source"
        rm -rf env/solana-conformance-repo
        git clone "$SOLANA_CONFORMANCE_REPO_URL" env/solana-conformance-repo
        git -C env/solana-conformance-repo checkout "$SOLANA_CONFORMANCE_REF"
        export SOLANA_CONFORMANCE_SRC="$PWD/env/solana-conformance-repo/solana-conformance"
        if [ ! -f "$SOLANA_CONFORMANCE_SRC/Cargo.toml" ]; then
          echo "ERROR: expected crate at $SOLANA_CONFORMANCE_SRC (Cargo.toml not found)."
          exit 1
        fi
        cargo install --locked --path "$SOLANA_CONFORMANCE_SRC" --root "$solana_conformance_install_root" || exit 1
        export PATH="$solana_conformance_install_root/bin:$PATH"
      elif [ -n "''${SOLANA_CONFORMANCE_SRC:-}" ]; then
        if [ ! -f "$SOLANA_CONFORMANCE_SRC/Cargo.toml" ]; then
          echo "ERROR: expected crate at $SOLANA_CONFORMANCE_SRC (Cargo.toml not found)."
          exit 1
        fi
        cargo install --locked --path "$SOLANA_CONFORMANCE_SRC" --root "$solana_conformance_install_root" || exit 1
        export PATH="$solana_conformance_install_root/bin:$PATH"
      elif command -v solana-conformance >/dev/null 2>&1; then
        echo "Using system solana-conformance from PATH: $(command -v solana-conformance)"
      else
        echo "ERROR: solana-conformance not found."
        echo "Set SOLANA_CONFORMANCE_REPO_URL and SOLANA_CONFORMANCE_REF,"
        echo "or set SOLANA_CONFORMANCE_SRC to the crate path (for example /path/to/repo/solana-conformance),"
        echo "or install solana-conformance so it is available on PATH."
        exit 1
      fi
      pip install -e parseout[dev]
    '';
  in {
    formatter.${system} = pkgs.alejandra;

    devShells.${system} = {
      default = pkgs.mkShell {
        packages = baseDeps;
        shellHook = baseShellHook;
      };

      agave = pkgs.mkShell {
        packages = baseDeps ++ (with pkgs; [clang cmake gcc pkgs.rust-bin.stable."1.93.0".default]);
        shellHook = baseShellHook + ''
          export LIBCLANG_PATH="${pkgs.llvmPackages_22.libclang.lib}/lib"
          export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [
            pkgs.stdenv.cc.cc.lib
            pkgs.llvmPackages_22.libclang.lib
            pkgs.llvmPackages_22.libllvm
          ]}"
          
          export PROTOC_EXECUTABLE="${protosol-toolchain}/protoc"
          export FLATC_EXECUTABLE="${protosol-toolchain}/flatc"
          
          [ ! -d env/agave ] && cp -r ${agave} env/agave && chmod +w -R env/agave
          [ ! -d env/sbpf ] && cp -r ${sbpf} env/sbpf && chmod +w -R env/sbpf
          [ ! -d env/solfuzz-agave ] && cp -r ${solfuzz-agave} env/solfuzz-agave && chmod +w -R env/solfuzz-agave
          [ ! -d env/solfuzz-agave/protosol ] && cp -r ${protosol} env/solfuzz-agave/protosol && chmod +w -R env/solfuzz-agave/protosol

          pushd env/solfuzz-agave
          python scripts/generate_local_cargo.py --agave-path ../agave --sbpf-path ../sbpf
          popd
        '';
      };
    };
  };
}
