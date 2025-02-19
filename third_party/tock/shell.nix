# Shell expression for the Nix package manager
#
# This nix expression creates an environment with necessary packages installed:
#
#  * `tockloader`
#  * rust
#
# To use:
#
#  $ nix-shell
#

{ pkgs ? import <nixpkgs> {} }:

with builtins;
let
  inherit (pkgs) stdenv lib;
  pythonPackages = lib.fix' (self: with self; pkgs.python3Packages //
  {

    tockloader = buildPythonPackage rec {
      pname = "tockloader";
      version = "1.6.0";
      name = "${pname}-${version}";

      propagatedBuildInputs = [ argcomplete colorama crcmod pyserial pytoml ];

      src = fetchPypi {
        inherit pname version;
        sha256 = "1aqkj1nplcw3gmklrhq6vxy6v9ad5mqiw4y1svasak2zkqdk1wyc";
      };
    };
  });
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  nixpkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };
  rust_date = "2021-01-07";
  rust_channel = "nightly";
  rust_targets = [
    "thumbv7em-none-eabi" "thumbv7em-none-eabihf" "thumbv6m-none-eabi"
    "riscv32imac-unknown-none-elf" "riscv32imc-unknown-none-elf" "riscv32i-unknown-none-elf"
  ];
  rust_build = nixpkgs.rustChannelOfTargets rust_channel rust_date rust_targets;
in
  with pkgs;
  stdenv.mkDerivation {
    name = "tock-dev";

    buildInputs = [
      python3Full
      pythonPackages.tockloader
      rust_build
      llvm
      qemu
    ];

    LD_LIBRARY_PATH="${stdenv.cc.cc.lib}/lib64:$LD_LIBRARY_PATH";

    # The defaults "objcopy" and "objdump" are wrong (for x86), use
    # "llvm-obj{copy,dump}" as defined in the makefile
    shellHook = ''
      unset OBJCOPY
      unset OBJDUMP
    '';
  }
