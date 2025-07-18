#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include "enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <psa/protected_storage.h>
#include <psa/crypto.h>
#include <string.h>
#include <tfm_ns_interface.h>
#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE (100)
#define NRF_CRYPTO_EXAMPLE_AES_BLOCK_SIZE (16)
#define NRF_CRYPTO_EXAMPLE_AES_IV_SIZE (12)
#define NRF_CRYPTO_EXAMPLE_AES_ADDITIONAL_SIZE (35)
#define NRF_CRYPTO_EXAMPLE_AES_GCM_TAG_LENGTH (16)
#define AES_KEY_SIZE (32)  // 128-bit key

/* Error codes for AES provisioning */
#define PROVISIONING_SUCCESS            (0)
#define PROVISIONING_ERROR_CRYPTO_INIT  (-100)
#define PROVISIONING_ERROR_KEY_IMPORT   (-101)
#define PROVISIONING_ERROR_KEY_OPEN     (-102)
#define PROVISIONING_ERROR_ENCRYPT      (-103)
#define PROVISIONING_ERROR_DECRYPT      (-104)
#define PROVISIONING_ERROR_IV_GEN       (-105)
#define PROVISIONING_ERROR_VERIFICATION (-106)
#define PROVISIONING_ERROR_KEY_DESTROY  (-107)

/* AES Key - Replace with your actual key */
static uint8_t m_aes_key[AES_KEY_SIZE] = {
    0xb4, 0xba, 0x59, 0x61, 0xcd, 0x43, 0xa8, 0xaf, 0xfa, 0xfd, 0xeb, 0xb1, 0x05, 0x92, 0x62, 0xee, 0x81, 0x8e, 0xe8, 0xc9, 0xfb, 0xd4, 0xfb, 0x13, 0x48, 0xbb, 0x9d, 0x57, 0xce, 0x58, 0x37, 0x37
};

/* Config data to encrypt - Replace with your actual config data */
static uint8_t m_config_data[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE] = {
    "Your config data goes here - replace this string"
};

/* Additional data for authentication - can be device ID, version, etc. */
static uint8_t m_additional_data[NRF_CRYPTO_EXAMPLE_AES_ADDITIONAL_SIZE] = {"Test"};

/* Buffers for encryption/decryption */
static uint8_t m_iv[NRF_CRYPTO_EXAMPLE_AES_IV_SIZE];
static uint8_t m_encrypted_data[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE + 
                                NRF_CRYPTO_EXAMPLE_AES_GCM_TAG_LENGTH];
static uint8_t m_decrypted_data[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];

static psa_key_id_t key_id = 2;  // Using persistent key ID 1
/* ====================================================================== */
#define PRINT_HEX(p_label, p_text, len)				  \
	({							  \
		LOG_INF("---- %s (len: %u): ----", p_label, len); \
		LOG_HEXDUMP_INF(p_text, len, "Content:");	  \
		LOG_INF("---- %s end  ----", p_label);		  \
	})


LOG_MODULE_REGISTER(aes_gcm, LOG_LEVEL_DBG);

int crypto_init(void)
{
    psa_status_t status;

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        LOG_INF("psa_crypto_init failed! (Error: %d)", status);
        return PROVISIONING_ERROR_CRYPTO_INIT;
    }

    return PROVISIONING_SUCCESS;
}

int crypto_finish(void)
{
    /* Note: For persistent keys, we typically don't destroy them
     * unless we specifically want to remove them from storage.
     * Uncomment the below code if you want to remove the key.
     */
    
    /*
    psa_status_t status;
    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        LOG_INF("psa_destroy_key failed! (Error: %d)", status);
        return PROVISIONING_ERROR_KEY_DESTROY;
    }
    */

    return PROVISIONING_SUCCESS;
}

int import_key(void)
{
    psa_status_t status;

    LOG_INF("Importing AES key with persistent ID 1...");

    /* Configure the key attributes */
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_id(&key_attributes, key_id);  // Set persistent key ID
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);  // Make key persistent
    psa_set_key_algorithm(&key_attributes, PSA_ALG_GCM);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attributes, 256);

    /* Import the key. If key already exists, this will return an error */
    status = psa_import_key(&key_attributes, m_aes_key, sizeof(m_aes_key), &key_id);
    if (status == PSA_ERROR_ALREADY_EXISTS) {
        LOG_INF("Key already exists, opening existing key...");
        /* Key already exists, just open it */
        status = psa_open_key(key_id, &key_id);
        if (status != PSA_SUCCESS) {
            LOG_INF("psa_open_key failed! (Error: %d)", status);
            psa_reset_key_attributes(&key_attributes);
            return PROVISIONING_ERROR_KEY_OPEN;
        }
    } else if (status != PSA_SUCCESS) {
        LOG_INF("psa_import_key failed! (Error: %d)", status);
        psa_reset_key_attributes(&key_attributes);
        return PROVISIONING_ERROR_KEY_IMPORT;
    }

    /* After the key handle is acquired the attributes are not needed */
    psa_reset_key_attributes(&key_attributes);

    LOG_INF("AES key imported successfully with persistent ID 1!");

    return PROVISIONING_SUCCESS;
}

int encrypt_config_data(uint8_t *config_data, size_t config_len, 
                       uint8_t *additional_data, size_t additional_len,
                       uint8_t *iv_out, uint8_t *encrypted_out, size_t *encrypted_len)
{
    psa_status_t status;

    LOG_INF("Encrypting config data using AES GCM MODE...");

    /* Generate a random IV */
    status = psa_generate_random(iv_out, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE);
    if (status != PSA_SUCCESS) {
        LOG_INF("psa_generate_random failed! (Error: %d)", status);
        return PROVISIONING_ERROR_IV_GEN;
    }

    /* Encrypt the config data and create the authentication tag */
    status = psa_aead_encrypt(key_id,
                              PSA_ALG_GCM,
                              iv_out,
                              NRF_CRYPTO_EXAMPLE_AES_IV_SIZE,
                              additional_data,
                              additional_len,
                              config_data,
                              config_len,
                              encrypted_out,
                              config_len + NRF_CRYPTO_EXAMPLE_AES_GCM_TAG_LENGTH,
                              encrypted_len);
    if (status != PSA_SUCCESS) {
        LOG_INF("psa_aead_encrypt failed! (Error: %d)", status);
        return PROVISIONING_ERROR_ENCRYPT;
    }

    LOG_INF("Encryption successful!");
    return PROVISIONING_SUCCESS;
}

int decrypt_config_data(uint8_t *encrypted_data, size_t encrypted_len,
                       uint8_t *iv, uint8_t *additional_data, size_t additional_len,
                       uint8_t *decrypted_out, size_t *decrypted_len)
{
    psa_status_t status;

    LOG_INF("Decrypting config data using AES GCM MODE...");

    /* Decrypt and authenticate the encrypted data */
    status = psa_aead_decrypt(key_id,
                              PSA_ALG_GCM,
                              iv,
                              NRF_CRYPTO_EXAMPLE_AES_IV_SIZE,
                              additional_data,
                              additional_len,
                              encrypted_data,
                              encrypted_len,
                              decrypted_out,
                              NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE,
                              decrypted_len);
    if (status != PSA_SUCCESS) {
        LOG_INF("psa_aead_decrypt failed! (Error: %d)", status);
        return PROVISIONING_ERROR_DECRYPT;
    }

    LOG_INF("Decryption and authentication successful!");
    return PROVISIONING_SUCCESS;
}

void print_provisioning_data(uint8_t *iv, uint8_t *encrypted_data, size_t encrypted_len, 
                            uint8_t *additional_data, size_t additional_len)
{
    LOG_INF("=== PROVISIONING DATA FOR TARGET DEVICE ===");
    LOG_INF("Store the following data in your target program:");
    LOG_INF("");
    
    LOG_INF("Key ID: %d (persistent)", key_id);
    LOG_INF("");
    
    PRINT_HEX("IV (12 bytes)", iv, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE);
    PRINT_HEX("Additional Data", additional_data, additional_len);
    PRINT_HEX("Encrypted Config Data", encrypted_data, encrypted_len);
    
    LOG_INF("");
    LOG_INF("=== C ARRAY FORMAT ===");
    
    // Print IV as C array
    LOG_INF("static uint8_t config_iv[%d] = {", NRF_CRYPTO_EXAMPLE_AES_IV_SIZE);
    for (int i = 0; i < NRF_CRYPTO_EXAMPLE_AES_IV_SIZE; i++) {
        if (i % 8 == 0) LOG_INF("    ");
        LOG_INF("0x%02x", iv[i]);
        if (i < NRF_CRYPTO_EXAMPLE_AES_IV_SIZE - 1) LOG_INF(", ");
        if ((i + 1) % 8 == 0) LOG_INF("");
    }
    LOG_INF("};");
    LOG_INF("");
    
    // Print encrypted data as C array
    LOG_INF("static uint8_t encrypted_config[%d] = {", encrypted_len);
    for (int i = 0; i < encrypted_len; i++) {
        if (i % 8 == 0) LOG_INF("    ");
        LOG_INF("0x%02x", encrypted_data[i]);
        if (i < encrypted_len - 1) LOG_INF(", ");
        if ((i + 1) % 8 == 0) LOG_INF("");
    }
    LOG_INF("};");
    LOG_INF("");
    
    // Print additional data as C array
    LOG_INF("static uint8_t additional_auth_data[%d] = {", additional_len);
    for (int i = 0; i < additional_len; i++) {
        if (i % 8 == 0) LOG_INF("    ");
        LOG_INF("0x%02x", additional_data[i]);
        if (i < additional_len - 1) LOG_INF(", ");
        if ((i + 1) % 8 == 0) LOG_INF("");
    }
    LOG_INF("};");
    LOG_INF("");
    
    LOG_INF("=== END PROVISIONING DATA ===");
}

int provision_config_data(void)
{
    int status;
    size_t encrypted_len;
    size_t decrypted_len;
    size_t config_len = strlen((char*)m_config_data);
    size_t additional_len = strlen((char*)m_additional_data);
    bool process_failed = false;

    LOG_INF("Starting AES-GCM Config Data Provisioning...");

    status = crypto_init();
    if (status != PROVISIONING_SUCCESS) {
        LOG_INF("Crypto initialization failed with error: %d", status);
        process_failed = true;
    }

    if (!process_failed) {
        status = import_key();
        if (status != PROVISIONING_SUCCESS) {
            LOG_INF("Key import failed with error: %d", status);
            process_failed = true;
        }
    }

    if (!process_failed) {
        status = encrypt_config_data(m_config_data, config_len,
                                    m_additional_data, additional_len,
                                    m_iv, m_encrypted_data, &encrypted_len);
        if (status != PROVISIONING_SUCCESS) {
            LOG_INF("Config data encryption failed with error: %d", status);
            process_failed = true;
        }
    }

    if (!process_failed) {
        /* Print the data needed for provisioning */
        print_provisioning_data(m_iv, m_encrypted_data, encrypted_len, 
                               m_additional_data, additional_len);

        /* Verify decryption works (optional test) */
        status = decrypt_config_data(m_encrypted_data, encrypted_len,
                                    m_iv, m_additional_data, additional_len,
                                    m_decrypted_data, &decrypted_len);
        if (status != PROVISIONING_SUCCESS) {
            LOG_INF("Config data decryption verification failed with error: %d", status);
            process_failed = true;
        }
    }

    if (!process_failed) {
        /* Check the validity of the decryption */
        if (memcmp(m_decrypted_data, m_config_data, config_len) != 0) {
            LOG_INF("Error: Decrypted data doesn't match the original config data");
            status = PROVISIONING_ERROR_VERIFICATION;
            process_failed = true;
        }
    }

    status = crypto_finish();
    if (status != PROVISIONING_SUCCESS) {
        LOG_INF("Crypto cleanup failed with error: %d", status);
        process_failed = true;
    }

    if (process_failed) {
        LOG_INF("Config data provisioning completed with errors!");
        return status;  // Return the last error code
    } else {
        LOG_INF("Config data provisioning completed successfully!");
        return PROVISIONING_SUCCESS;
    }
}