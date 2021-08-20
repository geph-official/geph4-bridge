#!/bin/sh

cargo build --release --locked --target x86_64-unknown-linux-musl
b2 upload-file geph-dl ./target/x86_64-unknown-linux-musl/release/geph4-bridge geph4-binaries/geph4-bridge-linux-amd64