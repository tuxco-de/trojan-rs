#!/bin/sh
# RUSTC_WRAPPER for Alpine/musl static builds.
#
# Problem: On Alpine (musl), the default +crt-static makes build scripts
# fully static, which disables dlopen(). bindgen needs dlopen() to load
# libclang.so. This wrapper applies +crt-static only to target crate
# compilations (which have --target in args) and forces -crt-static
# for build scripts / proc macros so dlopen() works.
#
# Cargo calls: RUSTC_WRAPPER <rustc-path> [args...]
# So $1 = rustc path, $@ = rustc path + all args.

for arg in "$@"; do
  if [ "$arg" = "--target" ]; then
    exec "$@" -C target-feature=+crt-static -C link-arg=-static-libstdc++ -C link-arg=-static-libgcc
  fi
done
exec "$@" -C target-feature=-crt-static
