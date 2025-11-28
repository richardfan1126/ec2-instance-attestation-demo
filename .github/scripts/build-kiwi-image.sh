#!/bin/bash

set -e

IMAGE_DESCRIPTION_DIR=${GITHUB_WORKSPACE}/kiwi-image-descriptions-examples/kiwi-image-descriptions-examples/al2023/attestable-image-example

# Building KIWI image inside container doesn't require sudo
# Replace command in `edit_boot_install.sh`:
#   from: `if sudo "$root_mount/usr/bin/nitro-tpm-pcr-compute"`
#   to:   `if "$root_mount/usr/bin/nitro-tpm-pcr-compute"`
sed -i 's/if sudo "$root_mount\/usr\/bin\/nitro-tpm-pcr-compute\"/if "$root_mount\/usr\/bin\/nitro-tpm-pcr-compute"/' \
    ${IMAGE_DESCRIPTION_DIR}/edit_boot_install.sh

################################
# Copy demo_api into the image #
################################
# Create directories for demo API service files
mkdir -p ${IMAGE_DESCRIPTION_DIR}/root/opt/demo_api
mkdir -p ${IMAGE_DESCRIPTION_DIR}/root/etc/systemd/system

# Copy demo API service files
cp ${GITHUB_WORKSPACE}/demo_api/demo_api.py ${IMAGE_DESCRIPTION_DIR}/root/opt/demo_api
cp ${GITHUB_WORKSPACE}/demo_api/demo_api.service ${IMAGE_DESCRIPTION_DIR}/root/etc/systemd/system

# Make demo_api.py executable
chmod +x ${IMAGE_DESCRIPTION_DIR}/root/opt/demo_api/demo_api.py

# Append systemctl enable command to config.sh to enable the service on boot
echo "" >> ${IMAGE_DESCRIPTION_DIR}/config.sh
echo "# Enable the demo API service" >> ${IMAGE_DESCRIPTION_DIR}/config.sh
echo "systemctl enable demo_api.service" >> ${IMAGE_DESCRIPTION_DIR}/config.sh

echo "Demo API service integration complete"

# Run build script using KIWI builder container
if ! docker run --rm \
    --privileged \
    -v /dev:/dev \
    -v ${IMAGE_DESCRIPTION_DIR}:/workspace \
    -v ${GITHUB_WORKSPACE}/build-output:/output \
    kiwi-builder:latest \
    bash -c "cd /workspace && kiwi-ng system build --description . --target-dir /output"; then
        echo "::error::KIWI NG build failed. Check the build logs above for details."
        exit 1
fi
