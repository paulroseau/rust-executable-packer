{
  pkgs ? import <nixpkgs> {}
}:

let
  ugdb = pkgs.callPackage ./ugdb.nix {};

in
  [
    ugdb
    pkgs.gdb
    pgks.nasm
  ]
