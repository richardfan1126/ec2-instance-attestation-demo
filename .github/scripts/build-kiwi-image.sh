#!/bin/bash

set -e

# Building KIWI image inside container doesn't require sudo
# Replace command in `edit_boot_install.sh`:
#   from: `if sudo "$root_mount/usr/bin/nitro-tpm-pcr-compute"`
#   to:   `if "$root_mount/usr/bin/nitro-tpm-pcr-compute"`
sed -i 's/if sudo "$root_mount\/usr\/bin\/nitro-tpm-pcr-compute\"/if "$root_mount\/usr\/bin\/nitro-tpm-pcr-compute"/' \
    ${GITHUB_WORKSPACE}/kiwi-image-descriptions-examples/kiwi-image-descriptions-examples/al2023/attestable-image-example/edit_boot_install.sh

# Run build script using KIWI builder container
if ! docker run --rm \
    --privileged \
    -v /dev:/dev \
    -v ${GITHUB_WORKSPACE}/kiwi-image-descriptions-examples/kiwi-image-descriptions-examples/al2023/attestable-image-example:/workspace \
    -v ${GITHUB_WORKSPACE}/build-output:/output \
    kiwi-builder:latest \
    bash -c "cd /workspace && kiwi-ng system build --description . --target-dir /output"; then
        echo "::error::KIWI NG build failed. Check the build logs above for details."
        exit 1
fi
