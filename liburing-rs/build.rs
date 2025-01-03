use std::{env, io::Write, path::PathBuf};

extern crate bindgen;

fn main() {
    println!("cargo::rerun-if-changed=src/");
    println!("cargo::rerun-if-changed=Makefile");
    println!("cargo::rerun-if-changed=Makefile.common");
    println!("cargo::rerun-if-changed=Makefile.quiet");
    println!("cargo::rerun-if-changed=configure");
    println!("cargo::rerun-if-changed=liburing-ffi.pc.in");
    println!("cargo::rerun-if-changed=liburing.spec");
    println!("cargo::rerun-if-changed=liburing.pc.in");
    println!("cargo::rerun-if-changed=liburing-rs/include/liburing_wrapper.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // copy everything in src to the OUT_DIR
    // Note, this brings along existing binary artifacts in the source tree
    std::process::Command::new("cp")
        .args([
            "-r",
            "src",
            "Makefile",
            "Makefile.common",
            "Makefile.quiet",
            "configure",
            "liburing-ffi.pc.in",
            "liburing.pc.in",
            "liburing.spec",
            out_path.to_str().unwrap(),
        ])
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    // if there are any binary artifacts in the source for OUT_DIR, clean them
    let r = std::process::Command::new("make")
        .args(["-C", "src", "clean"])
        .current_dir(out_path.clone())
        .output()
        .unwrap();

    std::io::stderr().write_all(&r.stderr).unwrap();
    assert!(r.status.success());

    let r = if cfg!(feature = "sanitizers") {
        std::process::Command::new("./configure")
            .current_dir(out_path.clone())
            .arg("--enable-sanitizer")
            .output()
            .unwrap()
    } else {
        std::process::Command::new("./configure")
            .current_dir(out_path.clone())
            .output()
            .unwrap()
    };

    std::io::stderr().write_all(&r.stderr).unwrap();
    assert!(r.status.success());

    println!("configured liburing repo");

    let r = std::process::Command::new("make")
        .args(["library", "-j12"])
        .current_dir(out_path.clone())
        .output()
        .unwrap();

    std::io::stderr().write_all(&r.stderr).unwrap();
    assert!(r.status.success());

    println!("completed `make library` call");

    let objcopy_cmd = std::env::var("OBJCOPY").unwrap_or(String::from("objcopy"));
    let r = std::process::Command::new(objcopy_cmd)
        .args(["--weaken-symbol", "io_uring_get_sqe", "src/liburing.a"])
        .current_dir(out_path.clone())
        .output()
        .unwrap();

    std::io::stderr().write_all(&r.stderr).unwrap();
    assert!(r.status.success());

    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}/src/include", out_path.to_str().unwrap()))
        .clang_arg("-std=c11")
        .clang_arg("-D_POSIX_C_SOURCE=200809L")
        .header("liburing-rs/include/liburing_wrapper.h")
        .anon_fields_prefix("__liburing_anon_")
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.

    bindings
        .write_to_file(out_path.join("liburing_bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("generated bindings");

    println!(
        "cargo::rustc-link-search={}/src",
        out_path.to_str().unwrap()
    );
    println!("cargo::rustc-link-lib=static=uring");
}
