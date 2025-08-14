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
#include "certs.h"
#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE (100)
#define NRF_CRYPTO_EXAMPLE_AES_BLOCK_SIZE (16)
#define NRF_CRYPTO_EXAMPLE_AES_IV_SIZE (12)
#define NRF_CRYPTO_EXAMPLE_AES_ADDITIONAL_SIZE (35)
#define NRF_CRYPTO_EXAMPLE_AES_GCM_TAG_LENGTH (16)
#define AES_KEY_SIZE (32)  // 256-bit key

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
#define PROVISIONING_ERROR_BUFFER_SIZE  (-108)

/* AES Key - Replace with your actual key */
/*

static uint8_t m_aes_key[AES_KEY_SIZE] = {
    0xb4, 0xba, 0x59, 0x61, 0xcd, 0x43, 0xa8, 0xaf, 0xfa, 0xfd, 0xeb, 0xb1, 0x05, 0x92, 0x62, 0xee, 0x81, 0x8e, 0xe8, 0xc9, 0xfb, 0xd4, 0xfb, 0x13, 0x48, 0xbb, 0x9d, 0x57, 0xce, 0x58, 0x37, 0x37
};
*/
/* Config data to encrypt - Replace with your actual config data */
static uint8_t m_config_data[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE] = {
    "ec2-18-234-99-151.compute-1.amazonaws.com"
};

/* Configuration variables as standalone globals */
static const char m_username[] = "admin";
static const char m_password[] = "Kalscott123";
static const char m_hostname[] = "18.234.99.151";
static const char m_mqtt_hostname[] = "mqtt.example.com";
 
/* Additional data for authentication - can be device ID, version, etc. */
static uint8_t m_additional_data[NRF_CRYPTO_EXAMPLE_AES_ADDITIONAL_SIZE] = {"Test"};

/* Only keep IV as global since it's needed for provisioning output */
static uint8_t m_iv[NRF_CRYPTO_EXAMPLE_AES_IV_SIZE];

#define AES_KEY_ID 0x00000005  // or any ID ≥ PSA_KEY_ID_USER_MIN

static psa_key_id_t persistent_key_id = AES_KEY_ID;  // Your persistent key ID
static psa_key_handle_t key_handle;                  // PSA runtime key handle

/* ====================================================================== */
#define PRINT_HEX(p_label, p_text, len)				  \
	({							  \
		LOG_INF("---- %s (len: %u): ----", p_label, len); \
		LOG_HEXDUMP_INF(p_text, len, "Content:");	  \
		LOG_INF("---- %s end  ----", p_label);		  \
	})

LOG_MODULE_REGISTER(aes_gcm_enc, LOG_LEVEL_DBG);

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

    LOG_INF("Importing AES key");

    /* Configure the key attributes */
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_id(&key_attributes, persistent_key_id);  // Set persistent key ID
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);  // Make key persistent
    psa_set_key_algorithm(&key_attributes, PSA_ALG_GCM);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attributes, 256);

    psa_key_attributes_t test_attr = PSA_KEY_ATTRIBUTES_INIT;

    status = psa_get_key_attributes(persistent_key_id, &test_attr);
    if (status == PSA_SUCCESS) {
        LOG_INF("Key exists, attempting to open...");
        status = psa_open_key(persistent_key_id, &key_handle);
        if (status != PSA_SUCCESS) {
            LOG_ERR("psa_open_key failed even though key attributes were found.");
            return PROVISIONING_ERROR_KEY_OPEN;
        }
    } 
    else if (status == PSA_ERROR_DOES_NOT_EXIST || status == PSA_ERROR_INVALID_HANDLE) {
        LOG_INF("Key not found, re-importing...");
        // Re-import key and set key_handle
        status = psa_import_key(&key_attributes, aes_key, AES_KEY_SIZE, &key_handle);
        if (status != PSA_SUCCESS) {
            LOG_ERR("psa_import_key failed: %d", status);
            return PROVISIONING_ERROR_KEY_IMPORT;
        }
    }
    LOG_INF("Key imported return status: %d", status);

    /* After the key handle is acquired the attributes are not needed */
    psa_reset_key_attributes(&key_attributes);

    LOG_INF("AES key imported successfully!");

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
    status = psa_aead_encrypt(persistent_key_id,
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
    status = psa_aead_decrypt(persistent_key_id,
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
    printk("\n=== PROVISIONING DATA (C array format) ===\n\n");
    k_sleep(K_MSEC(50));

    // IV
    printk("static uint8_t config_iv[%d] = {", NRF_CRYPTO_EXAMPLE_AES_IV_SIZE);
    for (size_t i = 0; i < NRF_CRYPTO_EXAMPLE_AES_IV_SIZE; i++) {
        printk("0x%02x", iv[i]);
        if (i < NRF_CRYPTO_EXAMPLE_AES_IV_SIZE - 1) printk(", ");
    }
    printk("};\n\n");
    k_sleep(K_MSEC(50));

    // Encrypted data
    printk("static uint8_t encrypted_config[%d] = {", (int)encrypted_len);
    for (size_t i = 0; i < encrypted_len; i++) {
        printk("0x%02x", encrypted_data[i]);
        if (i < encrypted_len - 1) printk(", ");
    }
    printk("};\n\n");
    k_sleep(K_MSEC(50));

    // Additional authenticated data (AAD)
    printk("static uint8_t additional_auth_data[%d] = {", (int)additional_len);
    for (size_t i = 0; i < additional_len; i++) {
        printk("0x%02x", additional_data[i]);
        if (i < additional_len - 1) printk(", ");
    }
    printk("};\n\n");
    k_sleep(K_MSEC(50));

    printk("=== END PROVISIONING DATA ===\n\n");
    k_sleep(K_MSEC(50));
}

/**
 * @brief Wrapper function for encrypting data and verifying decryption
 * @param config_data Data to encrypt
 * @param config_len Length of data to encrypt
 * @param additional_data Additional authenticated data
 * @param additional_len Length of additional data
 * @param iv_out Output buffer for IV
 * @param encrypted_out Output buffer for encrypted data
 * @param encrypted_len Output length of encrypted data
 * @return PROVISIONING_SUCCESS on success, error code on failure
 */
int encrypt_and_verify_data(uint8_t *config_data, size_t config_len,
                           uint8_t *additional_data, size_t additional_len,
                           uint8_t *iv_out, uint8_t *encrypted_out, size_t *encrypted_len)
{
    int status;
    
    /* Local buffers for verification */
    uint8_t decrypted_data[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
    size_t decrypted_len;

    /* Encrypt the data */
    status = encrypt_config_data(config_data, config_len,
                                additional_data, additional_len,
                                iv_out, encrypted_out, encrypted_len);
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("Encryption failed with error: %d", status);
        return status;
    }

    /* Print provisioning data */
    print_provisioning_data(iv_out, encrypted_out, *encrypted_len,
                           additional_data, additional_len);

    /* Verify decryption works (optional test) */
    status = decrypt_config_data(encrypted_out, *encrypted_len,
                                iv_out, additional_data, additional_len,
                                decrypted_data, &decrypted_len);
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("Decryption failed with error: %d", status);
        return status;
    }

    /* Verify the decrypted data matches original */
    if (memcmp(decrypted_data, config_data, config_len) != 0) {
        LOG_ERR("Error: Decrypted data doesn't match the original config data");
        return PROVISIONING_ERROR_VERIFICATION;
    }

    LOG_DBG("Data encryption and verification completed successfully!");
    return PROVISIONING_SUCCESS;
}

/**
 * @brief Encrypt a single configuration field with its own IV
 * @param field_name Name of the field for logging and AAD
 * @param field_data Data to encrypt
 * @return PROVISIONING_SUCCESS on success, error code on failure
 */
int encrypt_config_field(const char *field_name, const char *field_data)
{
    int status;
    size_t field_len;
    size_t additional_len;
    size_t encrypted_len;
    
    /* Local buffers for this field */
    uint8_t additional_data[NRF_CRYPTO_EXAMPLE_AES_ADDITIONAL_SIZE];
    uint8_t iv[NRF_CRYPTO_EXAMPLE_AES_IV_SIZE];
    uint8_t encrypted_data[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE + NRF_CRYPTO_EXAMPLE_AES_GCM_TAG_LENGTH];

    if (field_data == NULL || field_name == NULL) {
        LOG_ERR("Field data or name is NULL");
        return PROVISIONING_ERROR_VERIFICATION;
    }

    field_len = strlen(field_data);
    if (field_len >= NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE) {
        LOG_ERR("Field data too large: %s (len: %d)", field_name, field_len);
        return PROVISIONING_ERROR_BUFFER_SIZE;
    }

    LOG_DBG("\n=== Processing Field: %s (length: %d) ===", field_name, field_len);
    LOG_DBG("Field data: %s", field_name); // Don't log actual data for security
    
    /* Set field-specific additional authenticated data */
    snprintf((char*)additional_data, sizeof(additional_data), "Field_%s", field_name);
    additional_len = strlen((char*)additional_data);

    LOG_DBG("About to call encrypt_and_verify_data for field: %s", field_name);

    /* Encrypt and verify this field */
    status = encrypt_and_verify_data((uint8_t*)field_data, field_len,
                                    additional_data, additional_len,
                                    iv, encrypted_data, &encrypted_len);
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("Field encryption failed for %s: %d", field_name, status);
        return status;
    }

    LOG_DBG("=== Field %s processed successfully ===\n", field_name);
    return PROVISIONING_SUCCESS;
}

int provision_config_data(void)
{
    int status;
    size_t encrypted_len;
    size_t config_len = strlen((char*)m_config_data);
    size_t additional_len = strlen((char*)m_additional_data);
    bool process_failed = false;
    int field_errors = 0;
    
    /* Local buffers */
    uint8_t encrypted_data[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE + NRF_CRYPTO_EXAMPLE_AES_GCM_TAG_LENGTH];

    LOG_INF("Starting AES-GCM Config Data Provisioning...");

    status = crypto_init();
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("Crypto initialization error: %d", status);
        return status;
    }

    status = import_key();
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("Key import failed: %d", status);
        goto cleanup;
    }

    LOG_INF("Crypto initialized and key imported successfully.");
    k_sleep(K_MSEC(100)); // Delay for terminal readability

    /* First encrypt the original config data */
    LOG_DBG("\n=== Processing Original Config Data ===");
    status = encrypt_and_verify_data(m_config_data, config_len,
                                    m_additional_data, additional_len,
                                    m_iv, encrypted_data, &encrypted_len);
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("Original config data encryption failed: %d", status);
        process_failed = true;
    }
    k_sleep(K_MSEC(100)); // Delay for terminal readability

    /* Now encrypt each configuration field independently */
    LOG_DBG("\n=== Processing Individual Configuration Fields ===");
    LOG_DBG("Fields to process: username, password, hostname, mqtt_hostname");
    k_sleep(K_MSEC(100)); // Delay for terminal readability

    /* Username */
    LOG_DBG("Processing username field...");
    status = encrypt_config_field("username", m_username);
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("Username encryption failed: %d", status);
        field_errors++;
        process_failed = true;
    }
    k_sleep(K_MSEC(100)); // Delay for terminal readability

    /* Password */
    LOG_DBG("Processing password field...");
    status = encrypt_config_field("password", m_password);
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("Password encryption failed: %d", status);
        field_errors++;
        process_failed = true;
    }
    k_sleep(K_MSEC(100)); // Delay for terminal readability

    /* Hostname */
    LOG_DBG("Processing hostname field...");
    status = encrypt_config_field("hostname", m_hostname);
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("Hostname encryption failed: %d", status);
        field_errors++;
        process_failed = true;
    }
    k_sleep(K_MSEC(100)); // Delay for terminal readability

    /* MQTT Hostname */
    LOG_DBG("Processing mqtt_hostname field...");
    status = encrypt_config_field("mqtt_hostname", m_mqtt_hostname);
    if (status != PROVISIONING_SUCCESS) {
        LOG_ERR("MQTT hostname encryption failed: %d", status);
        field_errors++;
        process_failed = true;
    }
    k_sleep(K_MSEC(100)); // Delay for terminal readability

cleanup:
    int cleanup_status = crypto_finish();
    if (cleanup_status != PROVISIONING_SUCCESS) {
        LOG_ERR("Crypto cleanup failed with error: %d", cleanup_status);
        process_failed = true;
    }

    if (process_failed) {
        if (field_errors > 0) {
            LOG_ERR("Config data provisioning completed with %d field errors!", field_errors);
        } else {
            LOG_ERR("Config data provisioning completed with errors!");
        }
        return status;  // Return the last encryption error, not cleanup error
    } else {
        LOG_INF("All config data provisioning completed successfully!");
        return PROVISIONING_SUCCESS;
    }
}