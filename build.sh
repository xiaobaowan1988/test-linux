#!/bin/bash
# Reproduce: clone Linux kernel, build tinyconfig for arm64, generate compile_commands.json with Bear
set -e

KERNEL_DIR="${1:-/home/user/linux}"
ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-

# Clone latest kernel (shallow)
if [ ! -d "$KERNEL_DIR" ]; then
    git clone --depth=1 https://github.com/torvalds/linux.git "$KERNEL_DIR"
fi

cd "$KERNEL_DIR"

# Generate minimal arm64 config
make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE tinyconfig

# Build with Bear to capture compilation database
bear -- make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE -j"$(nproc)"

echo "compile_commands.json generated: $(wc -l < compile_commands.json) lines, $(python3 -c "import json; d=json.load(open('compile_commands.json')); print(len(d))") entries"
