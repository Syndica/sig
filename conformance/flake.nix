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
    baseDeps = with pkgs; [zigpkgs."0.15.2" python311 git alejandra];
    commits = builtins.fromTOML (builtins.readFile ./commits.env);

    test-vectors = builtins.fetchGit {
      url = "https://github.com/firedancer-io/test-vectors.git";
      rev = commits.TEST_VECTORS_COMMIT;
    };

    solana-conformance = builtins.fetchGit {
      url = "https://github.com/firedancer-io/solana-conformance.git";
      rev = commits.SOLANA_CONFORMANCE_COMMIT;
    };

    baseShellHook = ''
      export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [pkgs.stdenv.cc.cc.lib]}"
      mkdir -p env
      ln -sfn ${test-vectors} env/test-vectors

      python3.11 -m venv env/venv
      source env/venv/bin/activate
      cp -r ${solana-conformance} env/solana-conformance && chmod +w -R env/solana-conformance
      SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0 pip install env/solana-conformance[dev,octane]
    '';
  in {
    formatter.${system} = pkgs.alejandra;

    devShells.${system} = {
      default = pkgs.mkShell {
        packages = baseDeps;
        shellHook = baseShellHook;
      };

      full = pkgs.mkShell {
        packages = baseDeps ++ (with pkgs; [clang cmake gcc pkgs.rust-bin.stable."1.93.0".default]);
        shellHook = ''
          ${baseShellHook}
          export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [
            pkgs.stdenv.cc.cc.lib
            pkgs.llvmPackages_19.libclang.lib
          ]}"
          export LIBCLANG_PATH="${pkgs.llvmPackages_19.libclang.lib}/lib"
          scripts/get-solfuzz-agave.sh
        '';
      };
    };
  };
}
