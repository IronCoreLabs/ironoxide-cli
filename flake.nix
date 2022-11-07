{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nci = {
      url = "github:yusdacra/nix-cargo-integration";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
    };
  };

  outputs = inputs:
    with inputs; # pass through all inputs and bring them into scope
    nci.lib.makeOutputs {
      root = ./.;
      config = common: {
        #cachix.key = "";
        #cachix.name = "";
        outputs = {
          defaults = {
            app = "ironoxide-cli";
            package = "ironoxide-cli";
          };
        };
      };
      pkgConfig = common: {
        ironoxide-cli = {
          overrides.fix-build.overrideAttrs = prev: {
            buildInputs = nci.lib.nci-lib.addBuildInputs prev [ ]
              ++ nixpkgs.lib.optionals common.pkgs.stdenv.isDarwin
              [ common.pkgs.darwin.apple_sdk.frameworks.Security ];
          };
        };
      };
    };
}
