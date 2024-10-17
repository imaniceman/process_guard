#!/usr/bin/env just --justfile
set shell := ['powershell', '-NoProfile', '-Command']
release:
    cargo build --release

package: release
    python pack/pack.py