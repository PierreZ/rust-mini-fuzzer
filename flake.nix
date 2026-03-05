{
  description = "mini-fuzzer: coverage-guided fuzzing from first principles";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      {
        devShells.default = with pkgs; mkShell {
          buildInputs = [
            pkg-config
            (rust-bin.stable.latest.default.override {
              extensions = [
                "cargo"
                "clippy"
                "rust-src"
                "rustc"
                "rustfmt"
                "llvm-tools-preview"
              ];
            })
          ];

          RUST_BACKTRACE = "1";
        };
      }
    );
}
