#!/bin/bash
set -euo pipefail

MODE="${1:-local}"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

if command -v sudo >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
fi

if [[ "${MODE}" == "pico" ]]; then
    if command -v sudo >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y \
            build-essential \
            cmake \
            gcc-arm-none-eabi \
            libnewlib-arm-none-eabi \
            libstdc++-arm-none-eabi-newlib \
            libusb-1.0-0-dev \
            pkg-config \
            python3 \
            git
    fi

    if [[ ! -d pico-sdk ]]; then
        git clone https://github.com/raspberrypi/pico-sdk
        git -C pico-sdk checkout tags/2.1.1
        git -C pico-sdk submodule update --init
    fi

    if ! command -v picotool >/dev/null 2>&1; then
        if [[ ! -d picotool ]]; then
            git clone https://github.com/raspberrypi/picotool
            git -C picotool submodule update --init
        fi
        cmake -B picotool/build -S picotool -DPICO_SDK_PATH="${PWD}/pico-sdk"
        cmake --build picotool/build -j"${JOBS}"
        if command -v sudo >/dev/null 2>&1; then
            sudo cmake --install picotool/build
        else
            cmake --install picotool/build
        fi
    fi

    cmake -B build_pico \
        -DPICO_BOARD=waveshare_rp2350_one \
        -DPICO_SDK_PATH="${PWD}/pico-sdk" \
        -DVIDPID=Yubikey \
        -DENABLE_EDDSA=ON
    cmake --build build_pico -j"${JOBS}"
else
    if command -v sudo >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y \
            build-essential \
            cmake \
            git
    fi

    cmake -B build \
        -DENABLE_EMULATION=1 \
        -DVIDPID=Yubikey \
        -DENABLE_EDDSA=ON
    cmake --build build -j"${JOBS}"
    ctest --test-dir build --output-on-failure
fi
