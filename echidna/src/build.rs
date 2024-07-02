fn main() {
    // options for the linker - don't link with libc
    println!("cargo:rustc-link-arg-bin=echidna=-nostartfiles");
}
