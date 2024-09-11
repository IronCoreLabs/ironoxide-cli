{
  description = "A build for ironoxide-cli.";

  inputs = {
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rusttoolchain =
          pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in rec {
        # `nix build`
        packages = {
          ironoxide-cli = pkgs.rustPlatform.buildRustPackage {
            pname = "ironoxide-cli";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ rusttoolchain pkgs.libiconv ]
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin
              [ pkgs.darwin.apple_sdk.frameworks.SystemConfiguration ];
          };
        };
        defaultPackage = packages.ironoxide-cli;

        # nix develop
        devShell = pkgs.mkShell {
          buildInputs = with pkgs;
            [ rusttoolchain pkg-config pkgs.libiconv pkgs.prometheus ]
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin
            [ pkgs.darwin.apple_sdk.frameworks.SystemConfiguration ];
        };

      });
}
