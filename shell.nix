# shell.nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Rust toolchain
    rustc
    cargo
    rustfmt
    clippy
    
    # Required for oqs-sys compilation
    clang
    llvmPackages.libclang
    
    # Required for liboqs
    cmake
    ninja
    openssl
    pkg-config
    
    # Development tools
    git
    
    # Optional: for better crypto performance
    gcc
  ];
  
  # Environment variables needed for compilation
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
  BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.llvmPackages.libclang.version}/include";
}