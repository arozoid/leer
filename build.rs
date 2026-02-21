use std::env;

fn main() {
    let lkl_dir = env::var("LKL_DIR").unwrap_or_else(|_| ".".to_string());

    println!("cargo:rustc-link-search=native={}", lkl_dir);
    println!("cargo:rustc-link-search=native={}/lib", lkl_dir);
    println!("cargo:rustc-link-lib=static=lkl");

    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=rt");
}
