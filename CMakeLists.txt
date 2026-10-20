#
# This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
# Copyright (c) 2022 Pol Henarejos.
# Copyright (c) 2026 lazysaltyfish. Unified RP2350 & YubiKey 5 build system (2026-10).
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

cmake_minimum_required(VERSION 3.13)

if(NOT ENABLE_EMULATION)
    if(NOT DEFINED PICO_BOARD)
        set(PICO_BOARD waveshare_rp2350_one)
    endif()
    set(PICO_USE_FASTEST_SUPPORTED_CLOCK 1)
    include(pico_sdk_import.cmake)
endif()

project(pico_fido C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(NOT ENABLE_EMULATION)
    add_executable(pico_fido)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/cmake/version.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/options.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/build_helpers.cmake)

option(ENABLE_POWER_ON_RESET "Enable/disable power cycle on reset" ON)
configure_bool_option(
    ENABLE_POWER_ON_RESET
    ENABLE_POWER_ON_RESET
    "Power cycle on reset: \t enabled"
    "Power cycle on reset: \t disabled"
)

option(ENABLE_OATH_APP "Enable/disable OATH application" ON)
configure_bool_option(
    ENABLE_OATH_APP
    ENABLE_OATH_APP
    "OATH Application: \t\t enabled"
    "OATH Application: \t\t disabled"
)

option(ENABLE_OTP_APP "Enable/disable OTP application" ON)
configure_bool_option(
    ENABLE_OTP_APP
    ENABLE_OTP_APP
    "OTP Application: \t\t enabled"
    "OTP Application: \t\t disabled"
)

option(ENABLE_PIV_APP "Enable/disable PIV application" ON)
configure_bool_option(
    ENABLE_PIV_APP
    ENABLE_PIV_APP
    "PIV Application: \t\t enabled"
    "PIV Application: \t\t disabled"
)

option(ENABLE_OPENPGP_APP "Enable/disable OpenPGP application" ON)
configure_bool_option(
    ENABLE_OPENPGP_APP
    ENABLE_OPENPGP_APP
    "OpenPGP Application: \t\t enabled"
    "OpenPGP Application: \t\t disabled"
)

option(ENABLE_HSMAUTH_APP "Enable/disable YubiHSM Auth application" ON)
configure_bool_option(
    ENABLE_HSMAUTH_APP
    ENABLE_HSMAUTH_APP
    "YubiHSM Auth Application: \t enabled"
    "YubiHSM Auth Application: \t disabled"
)

option(ENABLE_SD_APP "Enable/disable Security Domain application" ON)
configure_bool_option(
    ENABLE_SD_APP
    ENABLE_SD_APP
    "Security Domain Application: \t enabled"
    "Security Domain Application: \t disabled"
)

if(FORBID_DISABLE_AUV)
    add_compile_definitions(FORBID_DISABLE_AUV=1)
endif()
if(DEFAULT_MCUV_NOT_REQUIRED)
    add_compile_definitions(DEFAULT_MCUV_NOT_REQUIRED=1)
endif()
if(DEFAULT_PIN_POLICY)
    add_compile_definitions(DEFAULT_PIN_POLICY=1)
endif()
if(MAX_PIN_RETRIES)
    add_compile_definitions(MAX_PIN_RETRIES=${MAX_PIN_RETRIES})
endif()
if(FORCE_BUTTON_WAIT)
    add_compile_definitions(FORCE_BUTTON_WAIT=1)
endif()

if(ENABLE_OTP_APP OR ENABLE_OATH_APP OR ENABLE_PIV_APP OR ENABLE_OPENPGP_APP OR ENABLE_HSMAUTH_APP OR ENABLE_SD_APP)
    set(USB_ITF_CCID 1)
    set(USB_ITF_WCID 1)
else()
    set(USB_ITF_CCID 0)
endif()
set(USB_ITF_HID 1)

option(VIDPID "Set USB VID/PID profile (default: Yubikey5 0x1050:0x0407)" "Yubikey5")
if(NOT VIDPID OR VIDPID STREQUAL "None" OR VIDPID STREQUAL "OFF" OR VIDPID STREQUAL "Yubikey" OR VIDPID STREQUAL "Yubikey5")
    set(VIDPID "Yubikey5")
    set(USB_VID 0x1050)
    set(USB_PID 0x0407)
elseif(VIDPID STREQUAL "YubikeyNeo")
    set(USB_VID 0x1050)
    set(USB_PID 0x0116)
elseif(VIDPID STREQUAL "YubiHSM")
    set(USB_VID 0x1050)
    set(USB_PID 0x0030)
endif()

if(NOT DEFINED USB_VID)
    set(USB_VID 0x1050)
endif()
if(NOT DEFINED USB_PID)
    set(USB_PID 0x0407)
endif()

message(STATUS "VIDPID:\t\t\t '${VIDPID}'")
message(STATUS "USB VID/PID:\t\t\t ${USB_VID}:${USB_PID}")

add_compile_definitions(
    USB_VID=${USB_VID}
    USB_PID=${USB_PID}
)

if(NOT DEFINED DEBUG_APDU)
    set(DEBUG_APDU 0)
endif()
if(NOT DEFINED ENABLE_EMULATION)
    set(ENABLE_EMULATION 0)
endif()

option(ENABLE_DELAYED_BOOT "Enable/disable delayed boot" OFF)
configure_bool_option(
    ENABLE_DELAYED_BOOT
    ""
    "Delayed boot:\t\t enabled"
    "Delayed boot:\t\t disabled"
)
if(ENABLE_DELAYED_BOOT)
    add_compile_definitions(PICO_XOSC_STARTUP_DELAY_MULTIPLIER=64)
endif()

if(USB_ITF_HID)
    add_compile_definitions(USB_ITF_HID=1)
    message(STATUS "USB HID Interface:\t\t enabled")
endif()
if(USB_ITF_CCID)
    add_compile_definitions(USB_ITF_CCID=1)
    message(STATUS "USB CCID Interface:\t\t enabled")
    if(USB_ITF_WCID)
        add_compile_definitions(USB_ITF_WCID=1)
        message(STATUS "USB WebCCID Interface:\t enabled")
    endif()
endif()

add_compile_definitions(
    DEBUG_APDU=${DEBUG_APDU}
    MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/config/mbedtls_config.h"
)
if(ENABLE_DIAGNOSTICS)
    add_compile_definitions(ENABLE_DIAGNOSTICS=1)
    message(STATUS "Persistent diagnostics:\t enabled")
endif()

include(${CMAKE_CURRENT_LIST_DIR}/cmake/deps.cmake)

set(MBEDTLS_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/aes.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/asn1parse.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/asn1write.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/bignum.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/bignum_core.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ccm.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/cmac.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/cipher.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/cipher_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/constant_time.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ecdsa.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ecdh.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ecp.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ecp_curves.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/gcm.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/hkdf.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/md.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/md5.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/oid.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pkcs5.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/platform_util.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/rsa.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/rsa_alt_helpers.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/sha1.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/sha256.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/sha512.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/chachapoly.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/chacha20.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/poly1305.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/ripemd160.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/des.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509write.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509write_crt.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509_create.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509write_csr.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/base64.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pem.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pk.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pk_wrap.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pkwrite.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/x509_crt.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pkparse.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pk_ecc.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/pkcs12.c
)

if(ENABLE_EDDSA)
    list(APPEND MBEDTLS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/eddsa.c
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/sha3.c
    )
endif()

if(NOT ENABLE_EMULATION AND NOT APPLE)
    set_source_files_properties(
        ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library/cmac.c
        PROPERTIES
        COMPILE_FLAGS "-Wno-error=stringop-overflow= -Wno-stringop-overflow"
    )
endif()

set(INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CMAKE_CURRENT_LIST_DIR}/src/usb
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid
    ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid
    ${CMAKE_CURRENT_LIST_DIR}/src/fs
    ${CMAKE_CURRENT_LIST_DIR}/src/rng
    ${CMAKE_CURRENT_LIST_DIR}/src/led
    ${CMAKE_CURRENT_LIST_DIR}/src/otp
    ${CMAKE_CURRENT_LIST_DIR}/src/fido
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/library
)

set(SYSTEM_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src
)

add_library(mbedtls STATIC ${MBEDTLS_SOURCES})
target_include_directories(mbedtls SYSTEM PUBLIC ${CMAKE_CURRENT_LIST_DIR}/third-party/mbedtls/include)

add_compile_options("-fmacro-prefix-map=${CMAKE_CURRENT_LIST_DIR}/=")

SET_BUILD_NUMBER("${CMAKE_CURRENT_LIST_DIR}")

set(CBOR_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src/cborencoder.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src/cborparser.c
    ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src/cborparser_dup_string.c
)
add_library(tinycbor STATIC ${CBOR_SOURCES})
target_include_directories(tinycbor PUBLIC ${CMAKE_CURRENT_LIST_DIR}/third-party/tinycbor/src)

if(ENABLE_EMULATION)
    add_compile_definitions(ENABLE_EMULATION)
    SET_VERSION(ver_major ver_minor "${CMAKE_CURRENT_LIST_DIR}/src/fido/version.h")
    enable_testing()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME verification_runner_test COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/tests/verification_runner_test.py")

    add_executable(hsmauth_security_test tests/hsmauth_security_test.c)
    target_include_directories(hsmauth_security_test PRIVATE ${INCLUDES} ${SYSTEM_INCLUDES})
    target_compile_options(hsmauth_security_test PRIVATE -Wall -Wextra -Wshadow -Werror -UNDEBUG)
    target_link_libraries(hsmauth_security_test PRIVATE mbedtls)
    add_test(NAME hsmauth_security_test COMMAND hsmauth_security_test)

    add_executable(fido_client_pin_test tests/fido_client_pin_test.c)
    target_include_directories(fido_client_pin_test PRIVATE ${INCLUDES} ${SYSTEM_INCLUDES})
    target_compile_options(fido_client_pin_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(fido_client_pin_test PRIVATE mbedtls tinycbor)
    add_test(NAME fido_client_pin_test COMMAND fido_client_pin_test)

    add_executable(piv_security_test tests/piv_security_test.c src/tlv.c)
    target_include_directories(piv_security_test PRIVATE ${INCLUDES} ${SYSTEM_INCLUDES})
    target_compile_options(piv_security_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(piv_security_test PRIVATE mbedtls)
    add_test(NAME piv_security_test COMMAND piv_security_test)

    add_executable(hsmauth_list_test tests/hsmauth_list_test.c)
    target_include_directories(hsmauth_list_test PRIVATE ${INCLUDES} ${SYSTEM_INCLUDES})
    target_compile_options(hsmauth_list_test PRIVATE -Wall -Wextra -Wshadow -Werror)
    target_link_libraries(hsmauth_list_test PRIVATE mbedtls)
    add_test(NAME hsmauth_list_test COMMAND hsmauth_list_test)

    add_executable(fido_oath_put_test tests/fido_oath_put_test.c src/fido/oath_put.c src/tlv.c)
    target_include_directories(fido_oath_put_test PRIVATE ${INCLUDES})
    target_compile_options(fido_oath_put_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(fido_oath_put_test PRIVATE mbedtls)
    add_test(NAME fido_oath_put_test COMMAND fido_oath_put_test)

    add_executable(fido_object_provider_test
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_crypto_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/tests/fido_object_provider_test.c
    )
    target_include_directories(fido_object_provider_test PRIVATE ${INCLUDES})
    target_compile_options(fido_object_provider_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(fido_object_provider_test PRIVATE mbedtls)
    add_test(NAME fido_object_provider_test COMMAND fido_object_provider_test)

    add_executable(fido_object_authorization_test
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_authorization.c
        ${CMAKE_CURRENT_LIST_DIR}/tests/fido_object_authorization_test.c
    )
    target_include_directories(fido_object_authorization_test PRIVATE ${INCLUDES})
    target_compile_options(fido_object_authorization_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(fido_object_authorization_test PRIVATE mbedtls)
    add_test(NAME fido_object_authorization_test COMMAND fido_object_authorization_test)

    add_executable(fido_resident_container_test
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container_store.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_crypto_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_policy.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_store_txn.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/resident_container.c
        ${CMAKE_CURRENT_LIST_DIR}/tests/fido_resident_container_test.c
    )
    target_include_directories(fido_resident_container_test PRIVATE ${INCLUDES})
    target_compile_options(fido_resident_container_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(fido_resident_container_test PRIVATE mbedtls)
    add_test(NAME fido_resident_container_test COMMAND fido_resident_container_test)

    add_executable(fido_oath_container_test
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container_store.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_crypto_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_policy.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_store_txn.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath_container.c
        ${CMAKE_CURRENT_LIST_DIR}/tests/fido_oath_container_test.c
    )
    target_include_directories(fido_oath_container_test PRIVATE ${INCLUDES})
    target_compile_options(fido_oath_container_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(fido_oath_container_test PRIVATE mbedtls)
    add_test(NAME fido_oath_container_test COMMAND fido_oath_container_test)

    add_executable(fido_otp_container_test
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container_store.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_crypto_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_policy.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_store_txn.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/otp_container.c
        ${CMAKE_CURRENT_LIST_DIR}/tests/fido_otp_container_test.c
    )
    target_include_directories(fido_otp_container_test PRIVATE ${INCLUDES})
    target_compile_options(fido_otp_container_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(fido_otp_container_test PRIVATE mbedtls)
    add_test(NAME fido_otp_container_test COMMAND fido_otp_container_test)

    add_executable(object_store_test
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_store.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_store_txn.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container_store.c
        ${CMAKE_CURRENT_LIST_DIR}/tests/object_store_test.c
    )
    target_include_directories(object_store_test PRIVATE ${INCLUDES})
    target_compile_options(object_store_test PRIVATE -Wall -Wextra -Werror)
    add_test(NAME object_store_test COMMAND object_store_test)

    add_executable(object_crypto_provider_test
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_crypto_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/tests/object_crypto_provider_test.c
    )
    target_include_directories(object_crypto_provider_test PRIVATE ${INCLUDES})
    target_compile_options(object_crypto_provider_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(object_crypto_provider_test PRIVATE mbedtls)
    add_test(NAME object_crypto_provider_test COMMAND object_crypto_provider_test)

    add_executable(object_policy_test
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_policy.c
        ${CMAKE_CURRENT_LIST_DIR}/tests/object_policy_test.c
    )
    target_include_directories(object_policy_test PRIVATE ${INCLUDES})
    target_compile_options(object_policy_test PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(object_policy_test PRIVATE mbedtls)
    add_test(NAME object_policy_test COMMAND object_policy_test)
else()
    pico_sdk_init()

    if(NOT PICO_RP2350)
        message(FATAL_ERROR "This repository only targets RP2350 boards (e.g. -DPICO_BOARD=waveshare_rp2350_one).")
    endif()

    SET_VERSION(ver_major ver_minor "${CMAKE_CURRENT_LIST_DIR}/src/fido/version.h")

    pico_set_uf2_family(${CMAKE_PROJECT_NAME} "rp2350-arm-s")
    pico_embed_pt_in_binary(${CMAKE_PROJECT_NAME} "${CMAKE_CURRENT_LIST_DIR}/config/rp2350/pt.json")
    if(SECURE_BOOT_PKEY)
        message(STATUS "Secure Boot Key ${SECURE_BOOT_PKEY}")
        pico_sign_binary(${CMAKE_PROJECT_NAME} ${SECURE_BOOT_PKEY})
        pico_hash_binary(${CMAKE_PROJECT_NAME})
    endif()

    list(APPEND INCLUDES
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt
    )
    target_include_directories(mbedtls PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt
    )
    target_link_libraries(mbedtls PRIVATE pico_sha256)
    add_compile_definitions(MBEDTLS_SHA256_ALT=1)

    set(SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/main.c
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb.c
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb_descriptors.c
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/hid/hid.c
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/ccid/ccid.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/file.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/vault_container.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_store.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_store_txn.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_container_store.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_policy.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/object_crypto_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/flash.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/low_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/phy.c
        ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp.c
        ${CMAKE_CURRENT_LIST_DIR}/src/otp/otp_rp2350.c
        ${CMAKE_CURRENT_LIST_DIR}/src/rng/random.c
        ${CMAKE_CURRENT_LIST_DIR}/src/rng/hwrng.c
        ${CMAKE_CURRENT_LIST_DIR}/src/crypto_utils.c
        ${CMAKE_CURRENT_LIST_DIR}/src/tlv.c
        ${CMAKE_CURRENT_LIST_DIR}/src/debug.c
        ${CMAKE_CURRENT_LIST_DIR}/src/apdu.c
        ${CMAKE_CURRENT_LIST_DIR}/src/rescue.c
        ${CMAKE_CURRENT_LIST_DIR}/src/serial.c
        ${CMAKE_CURRENT_LIST_DIR}/src/pico_time.c
        ${CMAKE_CURRENT_LIST_DIR}/src/button.c
        ${CMAKE_CURRENT_LIST_DIR}/src/led/led.c
        ${CMAKE_CURRENT_LIST_DIR}/src/led/led_pico.c
        ${CMAKE_CURRENT_LIST_DIR}/src/led/led_ws2812.c
        ${CMAKE_CURRENT_LIST_DIR}/src/signal.c
        ${CMAKE_CURRENT_LIST_DIR}/src/vault.c
        ${CMAKE_CURRENT_LIST_DIR}/config/rp2350/alt/sha256_alt.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/fido.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_authorization.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/object_provider.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/resident_container.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/files.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_register.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_authenticate.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_version.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_reset.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_get_info.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_make_credential.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/event.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/known_apps.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_client_pin.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/credential.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_get_assertion.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_selection.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_cred_mgmt.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_config.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_vendor.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/fido_vault.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_large_blobs.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/management.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/defs.c
    )

    if(ENABLE_OATH_APP)
        list(APPEND SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath_container.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath_put.c
        )
    endif()

    if(ENABLE_OTP_APP)
        list(APPEND SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/otp_container.c
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/otp.c
        )
    endif()

    if(ENABLE_PIV_APP)
        list(APPEND SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/piv.c
        )
    endif()

    if(ENABLE_OPENPGP_APP)
        list(APPEND SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/openpgp.c
        )
    endif()

    if(ENABLE_HSMAUTH_APP)
        list(APPEND SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/hsmauth.c
        )
    endif()

    if(ENABLE_SD_APP)
        list(APPEND SOURCES
            ${CMAKE_CURRENT_LIST_DIR}/src/fido/securitydomain.c
        )
    endif()

    target_sources(pico_fido PUBLIC ${SOURCES})
    target_include_directories(pico_fido PUBLIC ${INCLUDES})
    target_include_directories(pico_fido SYSTEM PUBLIC ${SYSTEM_INCLUDES})
    target_compile_options(pico_fido PRIVATE -Wall)

    picokeys_apply_strict_flags(
        SOURCES ${SOURCES}
        FILTER_REGEX "/src/|/config/"
    )

    string(FIND ${CMAKE_C_COMPILER} ":" COMPILER_COLON)
    if(${COMPILER_COLON} GREATER_EQUAL 0)
        target_compile_options(pico_fido PRIVATE -Wno-error=use-after-free)
    endif()

    target_link_libraries(
        pico_fido
        PRIVATE
            mbedtls
            tinycbor
            pico_bootrom
            pico_stdlib
            pico_multicore
            pico_rand
            pico_aon_timer
            hardware_flash
            hardware_sync
            hardware_adc
            hardware_pio
            pico_sha256
            pico_unique_id
            tinyusb_device
            tinyusb_board
    )
    pico_add_extra_outputs(${CMAKE_PROJECT_NAME})
endif()
