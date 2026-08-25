{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system;
          overlays = overlays;
        };
      in
      {
        devShells.default = with pkgs; mkShell {
          buildInputs = [
            (rust-bin.stable.latest.default.override {
              extensions = [ "clippy" "rust-src" "rustfmt" ];
              targets = [ "x86_64-pc-windows-msvc" ];
            })
            bacon
            sqlx-cli
          ];
        };
      }
    );
}
