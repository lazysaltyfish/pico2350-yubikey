/* Unsigned firmware cannot provision or lock secure boot. */
#ifndef PICO_SECURE_BOOT_KEY_H
#define PICO_SECURE_BOOT_KEY_H
#define PICO_SECURE_BOOT_KEY_CONFIGURED 0
static const unsigned char pico_secure_boot_key_hash[32] = { 0 };
#endif
