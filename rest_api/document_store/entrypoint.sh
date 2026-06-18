#!/bin/sh
set -e

# Entrypoint script: configure SoftHSM, initialize a token if missing,
# optionally generate an AES key, then run the main Go application.
#
# Expected environment variables:
# - HSM_TOKEN_LABEL: label for the SoftHSM token to create or detect
# - HSM_PIN: user and SO PIN used for token initialization and login
# - HSM_LABEL: label for the generated AES key object
echo "Automatically configuring SoftHSM..."

# 1) Configure SoftHSM to use the mounted tokens directory
mkdir -p /var/lib/softhsm/tokens
cat << EOF > /etc/softhsm/softhsm2.conf
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = INFO
EOF

# 2) Initialize the token only if it does not already exist
if ! softhsm2-util --show-slots | grep -q "${HSM_TOKEN_LABEL}"; then
    echo "Initializing token ${HSM_TOKEN_LABEL}..."
    softhsm2-util --init-token --free --label "${HSM_TOKEN_LABEL}" --pin "${HSM_PIN}" --so-pin "${HSM_PIN}"
    
    echo "Generating AES key..."
    # Use pkcs11-tool to generate a 256-bit AES key on the token
    pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
                --token "${HSM_TOKEN_LABEL}" \
                --login --pin "${HSM_PIN}" \
                --keygen --key-type aes:32 \
                --label "${HSM_LABEL}"
else
    echo "Token ${HSM_TOKEN_LABEL} already exists. Continuing to application."
fi

# 3) Execute the main Go binary produced by the Docker build.
# Update this path if your binary is located elsewhere in the image.
exec /app/main
