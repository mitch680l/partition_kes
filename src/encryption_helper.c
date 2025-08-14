
#include "config.h"
#include "encryption_helper.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/random/random.h>
#include <nrf_modem_at.h>
#include <modem/modem_key_mgmt.h>
#include <zephyr/sys/crc.h>
#include <zephyr/storage/flash_map.h>

psa_key_id_t my_key_id = 0x00000005;
psa_key_handle_t my_key_handle;
LOG_MODULE_REGISTER(encrption_helper, LOG_LEVEL_INF);
int open_persistent_key()
{
    psa_status_t status;

    status = psa_open_key(my_key_id, &my_key_handle);
    if (status != PSA_SUCCESS) {
        LOG_ERR("psa_open_key(0x%08x) failed: %d", my_key_id, status);
        return status;
    }

    LOG_INF("Persistent key 0x%08x opened successfully", my_key_id);
    return status;
}

int decrypt_config_field_data(const char *encrypted_data, size_t encrypted_len,
                              const char *iv,
                              const char *additional_data, size_t additional_len,
                              char *output_buf, size_t *output_len)
{
    if (!encrypted_data || !iv || !additional_data || !output_buf || !output_len) {
        LOG_ERR("Invalid input to decrypt_config_field_data");
        return PROVISIONING_ERROR_BUFFER_SIZE;
    }

    psa_status_t status;

    //LOG_INF("Decrypting config field...");

    status = psa_aead_decrypt(my_key_id,
                              PSA_ALG_GCM,
                              iv, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE,
                              additional_data, additional_len,
                              encrypted_data, encrypted_len,
                              output_buf, NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE,
                              output_len);

    if (status != PSA_SUCCESS) {
        LOG_ERR("Field decryption failed (psa_status: %d)", status);
        return PROVISIONING_ERROR_DECRYPT;
    }

    //LOG_INF("Field decryption successful (length: %u)", *output_len);
    return PROVISIONING_SUCCESS;
}

int encrypt_config_field_data(const char *plaintext_data, size_t plaintext_len,
                              char *iv_out,
                              const char *additional_data, size_t additional_len,
                              char *encrypted_out, size_t *encrypted_len)
{
    if (!plaintext_data || !iv_out || !additional_data || !encrypted_out || !encrypted_len) {
        LOG_ERR("Invalid input to encrypt_config_field_data");
        return PROVISIONING_ERROR_BUFFER_SIZE;
    }

    psa_status_t status;

    status = psa_generate_random((uint8_t*)iv_out, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE);
    if (status != PSA_SUCCESS) {
        LOG_ERR("IV generation failed (psa_status: %d)", status);
        return PROVISIONING_ERROR_IV_GEN;
    }

    LOG_INF("Encrypting config field...");

    status = psa_aead_encrypt(my_key_id,
                              PSA_ALG_GCM,
                              iv_out, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE,
                              additional_data, additional_len,
                              plaintext_data, plaintext_len,
                              encrypted_out, MAX_CIPHERTEXT_LEN,
                              encrypted_len);

    if (status != PSA_SUCCESS) {
        LOG_ERR("Field encryption failed (psa_status: %d)", status);
        return PROVISIONING_ERROR_ENCRYPT;
    }

    LOG_INF("Field encryption successful (length: %u)", *encrypted_len);
    return PROVISIONING_SUCCESS;
}


int create_encrypted_entry_with_aad(const char *plaintext_aad, const char *plaintext, uint8_t *entry_buf)
{
    if (!plaintext || !entry_buf || !plaintext_aad) return -EINVAL;

    char iv[NRF_CRYPTO_EXAMPLE_AES_IV_SIZE];
    static char encrypted[MAX_CIPHERTEXT_LEN];
    size_t encrypted_len;
    size_t plaintext_len = strlen(plaintext);
    size_t aad_len = strlen(plaintext_aad);

    int ret = encrypt_config_field_data(plaintext, plaintext_len,
                                        iv, plaintext_aad, aad_len,
                                        encrypted, &encrypted_len);
    if (ret != PROVISIONING_SUCCESS) {
        LOG_ERR("Encryption failed: %d", ret);
        return ret;
    }

    uint8_t *ptr = entry_buf;

    *ptr++ = NRF_CRYPTO_EXAMPLE_AES_IV_SIZE;
    memcpy(ptr, iv, NRF_CRYPTO_EXAMPLE_AES_IV_SIZE);
    ptr += NRF_CRYPTO_EXAMPLE_AES_IV_SIZE;

    *ptr++ = aad_len & 0xFF;
    *ptr++ = (aad_len >> 8) & 0xFF;
    memcpy(ptr, plaintext_aad, aad_len);
    ptr += aad_len;

    *ptr++ = encrypted_len & 0xFF;
    *ptr++ = (encrypted_len >> 8) & 0xFF;
    memcpy(ptr, encrypted, encrypted_len);
    ptr += encrypted_len;

    size_t used = ptr - entry_buf;
    if (used < ENTRY_SIZE) {
        memset(ptr, 0x00, ENTRY_SIZE - used);
    }

    LOG_INF("Created encrypted entry: AAD=\"%s\", len=%zu, plaintext_len=%zu, total_used=%zu",
            plaintext_aad, aad_len, plaintext_len, used);

    return 0;
}

