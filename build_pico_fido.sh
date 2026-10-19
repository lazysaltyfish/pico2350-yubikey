#!/bin/bash
set -euo pipefail

VERSION_MAJOR="8"
VERSION_MINOR="2"
VERSION_PATCH="1"
SUFFIX="${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}"
#if ! [[ -z "${GITHUB_SHA}" ]]; then
#    SUFFIX="${SUFFIX}.${GITHUB_SHA}"
#fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

if [[ -z "${PICO_SDK_PATH:-}" ]]; then
    if [[ -d "${ROOT_DIR}/pico-sdk" ]]; then
        PICO_SDK_PATH="${ROOT_DIR}/pico-sdk"
    elif [[ -d "${ROOT_DIR}/../pico-sdk" ]]; then
        PICO_SDK_PATH="$(cd "${ROOT_DIR}/../pico-sdk" && pwd)"
    elif [[ -d "/opt/pico-sdk" ]]; then
        PICO_SDK_PATH="/opt/pico-sdk"
    else
        PICO_SDK_PATH="../../pico-sdk"
    fi
elif [[ -d "${PICO_SDK_PATH}" ]]; then
    PICO_SDK_PATH="$(cd "${PICO_SDK_PATH}" && pwd)"
fi

if [[ -z "${SECURE_BOOT_PKEY:-}" && -f "${ROOT_DIR}/../ec_private_key.pem" ]]; then
    SECURE_BOOT_PKEY="$(cd "${ROOT_DIR}/.." && pwd)/ec_private_key.pem"
elif [[ -n "${SECURE_BOOT_PKEY:-}" && -f "${SECURE_BOOT_PKEY}" ]]; then
    SECURE_BOOT_PKEY="$(cd "$(dirname "${SECURE_BOOT_PKEY}")" && pwd)/$(basename "${SECURE_BOOT_PKEY}")"
else
    SECURE_BOOT_PKEY=""
fi

mkdir -p "${ROOT_DIR}/build_release"
mkdir -p "${ROOT_DIR}/release"
rm -rf -- "${ROOT_DIR}/release/"*
cd "${ROOT_DIR}/build_release"

boards=("waveshare_rp2350_one" "pico2")

for board_name in "${boards[@]}"
do
    rm -rf -- ./*
    CMAKE_ARGS=(
        -DPICO_BOARD="${board_name}"
        -DPICO_SDK_PATH="${PICO_SDK_PATH}"
        -DVIDPID=Yubikey
        -DENABLE_EDDSA=ON
    )
    if [[ -n "${SECURE_BOOT_PKEY}" ]]; then
        CMAKE_ARGS+=(-DSECURE_BOOT_PKEY="${SECURE_BOOT_PKEY}")
    fi
    cmake .. "${CMAKE_ARGS[@]}"
    make -j"${JOBS}"
    mv pico_fido.uf2 "${ROOT_DIR}/release/pico_fido_${board_name}-${SUFFIX}.uf2"
done
