/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

#include "basics.h"
#include "rng.h"
#include "stm32l4xx_hal.h"

// Details of the OTP area. 64-bit slots.
#define OPT_FLASH_BASE     0x1FFF7000
#define NUM_OPT_SLOTS      128

// This is what we're keeping secret... Kept in flash, written mostly once.
// fields must be 64-bit aligned so they can be written independently
typedef struct {
    // Pairing secret: picked once at factory when turned on
    // for the first time. Tied into all the secrets of the SE
    // on the same board.
    //
    uint8_t  pairing_secret[32];
    uint8_t  pairing_secret_xor[32];
    uint64_t ae_serial_number[2];       // 9 bytes active
    uint8_t  bag_number[32];            // 32 bytes max, zero padded string
    uint8_t  otp_key[72];               // key for secret encryption (seed storage)
    uint8_t  otp_key_long[416];         // same, but for longer secret area
    uint8_t  hash_cache_secret[32];     // encryption for cached pin hash value

    // SE2 items
    uint8_t     se2_pairing[32] __attribute__((aligned(8)));
    uint8_t     se2_pubkey_A[64];
    uint8_t     se2_romid[8];           // serial number
    uint8_t     se2_spare[24];

    // ... plus lots more space ...
} rom_secrets_t;

// This area is defined in linker script as last page of boot loader flash.
#define rom_secrets         ((rom_secrets_t *)BL_NVROM_BASE)

// Call at boot time. Picks pairing secret and/or verifies it.
void flash_setup(void);

// Set option-bytes region to appropriate values
void flash_lockdown_hard(uint8_t rdp_level_code);

// Save a serial number from secure element
void flash_save_ae_serial(const uint8_t serial[9]);

// Write bag number (probably a string)
void flash_save_bag_number(const uint8_t new_number[32]);

// Are we operating in level2?
static inline bool flash_is_security_level2(void) {
    rng_delay();
    return ((FLASH->OPTR & FLASH_OPTR_RDP_Msk) == 0xCC);
}

// generial purpose flash functions
void flash_setup0(void);
void flash_lock(void);
void flash_unlock(void);
int flash_burn(uint32_t address, uint64_t val);
int flash_burn_fast(uint32_t address, const uint32_t values[128]);
int flash_page_erase(uint32_t address);

// write to OTP
int record_highwater_version(const uint8_t timestamp[8]);

// EOF
