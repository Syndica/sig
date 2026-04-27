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
    baseDeps = with pkgs; [zigpkgs."0.15.2" python313 git alejandra];
    commits = builtins.fromTOML (builtins.readFile ./commits.env);

    test-vectors = builtins.fetchGit {
      url = "https://github.com/firedancer-io/test-vectors.git";
      rev = commits.TEST_VECTORS_COMMIT;
    };
    solana-conformance = builtins.fetchGit {
      url = "https://github.com/firedancer-io/solana-conformance.git";
      rev = commits.SOLANA_CONFORMANCE_COMMIT;
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
      cp -r ${solana-conformance} env/solana-conformance && chmod +w -R env/solana-conformance
      export SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0
      pip install -e env/solana-conformance[dev,octane]
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
