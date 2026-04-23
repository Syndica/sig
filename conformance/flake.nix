{
  description = "Sig Conformance Testing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Pinned nixpkgs for abseil-cpp 20250512.1 (required by solfuzz protobuf)
    nixpkgs-abseil.url = "github:NixOS/nixpkgs/648f70160c03151bc2121d179291337ad6bc564b";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    nixpkgs-abseil,
    zig-overlay,
    rust-overlay,
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [rust-overlay.overlays.default zig-overlay.overlays.default];
    };
    pkgs-abseil = import nixpkgs-abseil {inherit system;};
    baseDeps = with pkgs; [zigpkgs."0.15.2" python313 git alejandra];
    commits = builtins.fromTOML (builtins.readFile ./commits.env);
    llvmPackages = pkgs.llvmPackages_20;

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
    protosol = builtins.fetchGit {
      url = "https://github.com/firedancer-io/protosol.git";
      rev = commits.AGAVE_PROTOSOL_COMMIT;
      submodules = true;
    };
    agave = builtins.fetchGit {
      url = "https://github.com/firedancer-io/agave.git";
      rev = commits.AGAVE_COMMIT;
    };
    sbpf = builtins.fetchGit {
      url = "https://github.com/firedancer-io/sbpf.git";
      rev = commits.SBPF_COMMIT;
    };
    solfuzz  = builtins.fetchGit {
      url = "https://github.com/firedancer-io/solfuzz.git";
      rev = "15e02a456519ac54db58878f7c249652087c84d8";
      submodules = true;
    };

    # protoc and flatc need to be the exact versions built by protosol
    protosol-toolchain = pkgs.stdenvNoCC.mkDerivation {
      pname = "protosol-toolchain";
      version = commits.AGAVE_PROTOSOL_COMMIT;
      src = protosol;
      nativeBuildInputs = with pkgs; [ cmake gcc ];
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

    # # 
    # solfuzz-toolchain = pkgs.stdenvNoCC.mkDerivation {
    #   pname = "solfuzz-toolchain";
    #   version = commits.SOLFUZZ_COMMIT;
    #   src = solfuzz;
    #   nativeBuildInputs = with pkgs; [ git clang lld cmake gcc openssl pkg-config binutils libunwind libblocksruntime ];
    #   dontConfigure = true;
    #   buildPhase = ''
    #     patchShebangs ./sys/deps.sh
    #     ./sys/deps.sh
    #   '';
    #   installPhase = ''
    #     mkdir -p "$out"
    #     cp -r opt/* "$out"
    #   '';
    # };

    baseShellHook = ''
      export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [pkgs.stdenv.cc.cc.lib]}"
      mkdir -p env
      ln -sfn ${test-vectors} env/test-vectors

      # python3.13 -m venv env/venv
      # source env/venv/bin/activate
      # ln -sfn "$PWD/run.py" env/venv/bin/run
      # cp -r ${solana-conformance} env/solana-conformance && chmod +w -R env/solana-conformance
      # export SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0
      # pip install -e env/solana-conformance[dev,octane]
      # pip install -e parseout[dev]
    '';
  in {
    formatter.${system} = pkgs.alejandra;

    devShells.${system} = {
      default = pkgs.mkShell {
        packages = baseDeps;
        shellHook = baseShellHook;
      };

      agave = pkgs.mkShell {
        hardeningDisable = ["fortify"];
        packages = baseDeps ++ (with pkgs; [
          llvmPackages.clang cmake gcc pkgs.rust-bin.stable."1.93.0".default git lld openssl
          pkg-config binutils binutils-unwrapped libunwind libblocksruntime pkgs-abseil.abseil-cpp
        ]);
        shellHook = baseShellHook + ''
          export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
          export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [
            pkgs.stdenv.cc.cc.lib
            pkgs.llvmPackages.libclang.lib
            pkgs.llvmPackages.libllvm
          ]}"
          
          export PROTOC_EXECUTABLE="${protosol-toolchain}/protoc"
          export FLATC_EXECUTABLE="${protosol-toolchain}/flatc"
          
          [ ! -d env/agave ] && cp -r ${agave} env/agave && chmod +w -R env/agave
          [ ! -d env/sbpf ] && cp -r ${sbpf} env/sbpf && chmod +w -R env/sbpf
          [ ! -d env/solfuzz-agave ] && cp -r ${solfuzz-agave} env/solfuzz-agave && chmod +w -R env/solfuzz-agave
          [ ! -d env/solfuzz-agave/protosol ] && cp -r ${protosol} env/solfuzz-agave/protosol && chmod +w -R env/solfuzz-agave/protosol
          [ ! -d env/solfuzz ] && cp -r ${solfuzz} env/solfuzz && chmod +w -R env/solfuzz

          pushd env/solfuzz-agave
          python scripts/generate_local_cargo.py --agave-path ../agave --sbpf-path ../sbpf
          popd
        '';
      };
    };
  };
}
