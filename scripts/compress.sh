#!/bin/sh
# --------------------------------------------------------------------------
# compress.sh - Build and package exploit into initramfs
#
# Author: Axura
# Website: https://4xura.com
#
# Usage:
#   ./compress.sh <exploit_source.c> [output_binary_name]
#
# Description:
#   - Compiles a statically linked exploit binary from the given C source
#   - Moves the binary into the 'initramfs/' directory
#   - Packs the initramfs directory into 'initramfs.cpio.gz' using cpio+gzip
#
# Example:
#   ./compress.sh exploit.c
#   ./compress.sh exploit.c custom_name
# --------------------------------------------------------------------------

set -euo pipefail

SRC_FILE="$1"
BIN_NAME="${2:-exploit}"
INITRAMFS_DIR="./initramfs"
OUTPUT_NAME="initramfs.cpio.gz"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <exploit_source.c> [output_binary_name]"
    exit 1
fi

if [ ! -f "$SRC_FILE" ]; then
    echo "Error: source file '$SRC_FILE' not found."
    exit 1
fi

if [ ! -d "$INITRAMFS_DIR" ]; then
    echo "Error: '$INITRAMFS_DIR' directory not found."
    exit 1
fi

echo "[*] Compiling '$SRC_FILE' statically..."
gcc -o "$BIN_NAME" -static "$SRC_FILE"

echo "[*] Moving '$BIN_NAME' into '$INITRAMFS_DIR/'..."
mv "./$BIN_NAME" "$INITRAMFS_DIR/"

cd "$INITRAMFS_DIR"

echo "[*] Repacking initramfs to ../$OUTPUT_NAME..."
find . -print0 \
    | cpio --null -ov --format=newc \
    | gzip -9 > "../$OUTPUT_NAME"

cd ..

echo "[+] Done: $OUTPUT_NAME created."

