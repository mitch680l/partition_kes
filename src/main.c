#include <zephyr/kernel.h>
#include "certs.h"
#include <modem/modem_key_mgmt.h>
#include <modem/nrf_modem_lib.h>
#include <nrf_modem_gnss.h>
#include <nrf_modem_at.h>
#include <modem/lte_lc.h>
#include <zephyr/shell/shell.h>
#include <psa/protected_storage.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tfm_ns_interface.h>
#include "fota.h"
#include "enc.h"
#include "test.h"
#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/init.h>
#include <zephyr/sys/printk.h>
// Replace with your secure tag
#define TLS_SEC_TAG 42

// TF-M Protected Storage UID

#define PBKDF2_ITERATIONS 150000u


LOG_MODULE_REGISTER(hmac, LOG_LEVEL_DBG);
#define HMAC_KEY_ID ((psa_key_id_t)0x6001)
#define HMAC_KEY_LEN 32

#define MAX_INPUT_LEN 256
#define BLOB_HEADER_SIZE 0
#define ENTRY_SIZE 128
#define MAX_ENTRIES         16
#define MAX_IV_LEN          16
#define MAX_AAD_LEN         64
#define MAX_CIPHERTEXT_LEN  256
#define FLASH_PAGE_SIZE  4096 
#define ENTRIES_PER_PAGE (FLASH_PAGE_SIZE / ENTRY_SIZE)
#define CONFIG_PAGE_COUNT 2  
#define TOTAL_ENTRIES     (CONFIG_PAGE_COUNT * ENTRIES_PER_PAGE) 
#define ENCRYPTED_BLOB_ADDR ((const uint8_t *)0xfb000)
#define ENCRYPTED_BLOB_SIZE 8192 
#define FLASH_CRC_PAGE_OFFSET (CONFIG_PAGE_COUNT * FLASH_PAGE_SIZE)
#define FLASH_PAGE_CRC_SIZE  (ENCRYPTED_BLOB_SIZE - FLASH_CRC_PAGE_OFFSET)
#define CRC_LOCATION_OFFSET (ENCRYPTED_BLOB_SIZE - 4)

typedef struct {
    uint8_t iv[MAX_IV_LEN];
    uint8_t iv_len;

    uint8_t aad[MAX_AAD_LEN];
    uint16_t aad_len;

    uint8_t ciphertext[MAX_CIPHERTEXT_LEN];
    uint16_t ciphertext_len;

    uint32_t mem_offset;  // absolute memory offset of the entry
} ConfigEntry;

static ConfigEntry entries[MAX_ENTRIES];
static int num_entries = 0;

static inline uint16_t read_u16_le(const uint8_t *p) {
    return p[0] | (p[1] << 8);
}

static inline uint32_t read_u32_le(const uint8_t *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}


static bool aad_equals_key(const ConfigEntry *e, const char *key)
{
    size_t klen = strlen(key);
    return (e->aad_len == klen) && (memcmp(e->aad, key, klen) == 0);
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = (char)tolower((unsigned char)c);
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return -1;
}

static bool hex_to_bytes(const char *hex, size_t hex_len, uint8_t *out, size_t *out_len)
{
    if ((hex_len & 1u) != 0u) return false;
    size_t n = hex_len / 2u;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(hex[2*i]);
        int lo = hex_nibble(hex[2*i+1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return true;
}

static int consttime_cmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff; /* 0 == equal */
}

/* Decrypt entry value into ASCII buffer (NUL terminated). */
static int decrypt_entry_value_ascii(const ConfigEntry *e, char *out, size_t out_cap, size_t *out_len)
{
    size_t plain_len = 0;
    if (out_cap == 0) return -1;

    int rc = decrypt_config_data(e->ciphertext, e->ciphertext_len,
                                 (uint8_t *)e->iv,
                                 (uint8_t *)e->aad, e->aad_len,
                                 (uint8_t *)out, &plain_len);
    if (rc != 1) {
        LOG_INF("decrypt_config_data failed for AAD '%.*s'", e->aad_len, e->aad);
        return rc;
    }
    if (plain_len >= out_cap) {
        LOG_INF("decrypted value too long for buffer");
        return -2;
    }
    out[plain_len] = '\0';
    if (out_len) *out_len = plain_len;
    return 0;
}

/* Find and decrypt config value for a given key name. Tries both pdkdf2.* and pbkdf2.* */
static int get_config_ascii_by_key(const char *key_primary, const char *key_fallback,
                                   char *out, size_t out_cap, size_t *out_len)
{
    for (int pass = 0; pass < 2; pass++) {
        const char *key = (pass == 0) ? key_primary : key_fallback;
        if (!key) continue;
        for (int i = 0; i < num_entries; i++) {
            const ConfigEntry *e = &entries[i];
            if (aad_equals_key(e, key)) {
                return decrypt_entry_value_ascii(e, out, out_cap, out_len);
            }
        }
    }
    return -3; /* not found */
}

/* Derive PBKDF2-HMAC-SHA256 using PSA; out_len determines DK length */
static int derive_pbkdf2_sha256(const uint8_t *password, size_t pw_len,
                                const uint8_t *salt, size_t salt_len,
                                uint32_t iterations,
                                uint8_t *out, size_t out_len)
{
    psa_status_t st;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (st != PSA_SUCCESS) goto done;

    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, iterations);
    if (st != PSA_SUCCESS) goto done;

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
    if (st != PSA_SUCCESS) goto done;

    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, password, pw_len);
    if (st != PSA_SUCCESS) goto done;

    st = psa_key_derivation_output_bytes(&op, out, out_len);

done:
    psa_key_derivation_abort(&op);
    return (st == PSA_SUCCESS) ? 0 : -1;
}

/* ---- The test you asked for ----
   Uses password "Kalscott123" (correct) and "NotThePassword!" (wrong) */
int test_pbkdf2_verify_from_blob(void)
{
    /* 1) Fetch and decrypt salt + hash from entries[] */
    char salt_hex[128]; size_t salt_hex_len = 0;
    char hash_hex[256]; size_t hash_hex_len = 0;

    int rc;

    rc = get_config_ascii_by_key("pdkdf2.salt", "pbkdf2.salt",
                                 salt_hex, sizeof(salt_hex), &salt_hex_len);
    if (rc) {
        LOG_INF("Salt not found/decrypt failed (rc=%d)", rc);
        return rc;
    }

    rc = get_config_ascii_by_key("pdkdf2.hash", "pbkdf2.hash",
                                 hash_hex, sizeof(hash_hex), &hash_hex_len);
    if (rc) {
        LOG_INF("Hash not found/decrypt failed (rc=%d)", rc);
        return rc;
    }

    /* 2) Hex-decode both */
    uint8_t salt[64]; size_t salt_len = 0;
    uint8_t hash_ref[64]; size_t hash_len = 0;

    if (!hex_to_bytes(salt_hex, salt_hex_len, salt, &salt_len)) {
        LOG_INF("Salt hex decode failed");
        return -4;
    }
    if (!hex_to_bytes(hash_hex, hash_hex_len, hash_ref, &hash_len)) {
        LOG_INF("Hash hex decode failed");
        return -5;
    }

    /* 3) Derive with the correct password */
    const char *good_pw = "Kalscott123";
    uint8_t cand_good[64];
    if (hash_len > sizeof(cand_good)) {
        LOG_INF("Stored hash too long");
        return -6;
    }
    rc = derive_pbkdf2_sha256((const uint8_t *)good_pw, strlen(good_pw),
                              salt, salt_len, PBKDF2_ITERATIONS,
                              cand_good, hash_len);
    if (rc) {
        LOG_INF("PBKDF2 derive failed for correct password");
        return rc;
    }

    int eq_good = consttime_cmp(cand_good, hash_ref, hash_len);
    LOG_INF("PBKDF2 verify (correct pw): %s", (eq_good == 0) ? "PASS" : "FAIL");

    /* 4) Derive with a wrong password */
    const char *bad_pw = "NotThePassword!";
    uint8_t cand_bad[64];
    rc = derive_pbkdf2_sha256((const uint8_t *)bad_pw, strlen(bad_pw),
                              salt, salt_len, PBKDF2_ITERATIONS,
                              cand_bad, hash_len);
    if (rc) {
        LOG_INF("PBKDF2 derive failed for wrong password");
        return rc;
    }

    int eq_bad = consttime_cmp(cand_bad, hash_ref, hash_len);
    LOG_INF("PBKDF2 verify (wrong pw):   %s", (eq_bad == 0) ? "PASS (unexpected)" : "FAIL (expected)");

    /* 5) Return overall status: 0 if good passed and bad failed */
    return (eq_good == 0 && eq_bad != 0) ? 0 : -7;
}

uint32_t manual_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;

    LOG_INF("Starting manual CRC-32 over %u bytes", (unsigned int)len);

    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        crc ^= byte;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }

    crc ^= 0xFFFFFFFF;

    LOG_INF("Final manual CRC-32: 0x%08X", crc);
    return crc;
}


void parse_encrypted_blob(void)
{
    const uint8_t *start = ENCRYPTED_BLOB_ADDR;
    const uint8_t *end = ENCRYPTED_BLOB_ADDR + ENCRYPTED_BLOB_SIZE;
    const size_t entry_span = ENTRY_SIZE;
    const size_t max_offset = CRC_LOCATION_OFFSET;

    LOG_INF("Begin blob parsing at address %p, total size: %d", (void *)start, ENCRYPTED_BLOB_SIZE);

    uint32_t computed_crc = manual_crc32(start, ENCRYPTED_BLOB_SIZE - 4);
    uint32_t stored_crc = *(uint32_t *)(start + CRC_LOCATION_OFFSET);
    if (computed_crc != stored_crc) {
        LOG_WRN("CRC mismatch: computed=0x%08X, stored=0x%08X", computed_crc, stored_crc);
    } else {
        LOG_INF("CRC check passed: 0x%08X", computed_crc);
    }

    num_entries = 0;

    for (uintptr_t offset = 0; offset + entry_span <= max_offset && num_entries < MAX_ENTRIES; offset += entry_span) {
        const uint8_t *ptr = start + offset;

        if (ptr[0] == 0xFF) {
            continue;
        }

        ConfigEntry *e = &entries[num_entries];
        e->mem_offset = offset;

        e->iv_len = *ptr++;
        if (e->iv_len > MAX_IV_LEN || ptr + e->iv_len > end) {
            LOG_ERR("Invalid or oversized IV length: %d at entry %d", e->iv_len, num_entries);
            continue;
        }
        memcpy(e->iv, ptr, e->iv_len);
        ptr += e->iv_len;

        if (ptr + 2 > end) continue;
        e->aad_len = ptr[0] | (ptr[1] << 8);
        ptr += 2;
        if (e->aad_len > MAX_AAD_LEN || ptr + e->aad_len > end) {
            LOG_ERR("Invalid or oversized AAD length: %d at entry %d", e->aad_len, num_entries);
            continue;
        }
        memcpy(e->aad, ptr, e->aad_len);
        ptr += e->aad_len;

        if (ptr + 2 > end) continue;
        e->ciphertext_len = ptr[0] | (ptr[1] << 8);
        ptr += 2;
        if (e->ciphertext_len > MAX_CIPHERTEXT_LEN || ptr + e->ciphertext_len > end) {
            LOG_ERR("Invalid or oversized ciphertext length: %d at entry %d", e->ciphertext_len, num_entries);
            continue;
        }
        memcpy(e->ciphertext, ptr, e->ciphertext_len);
        ptr += e->ciphertext_len;

        LOG_INF("Parsed entry %d @ offset 0x%04X: IV=%d, AAD=%d, Cipher+Tag=%d",
                num_entries, (int)offset, e->iv_len, e->aad_len, e->ciphertext_len);

        num_entries++;
    }

    LOG_INF("Total parsed entries: %d", num_entries);
}

#define NRF_CRYPTO_EXAMPLE_HMAC_TEXT_SIZE (100)
#define NRF_CRYPTO_EXAMPLE_HMAC_KEY_SIZE (32)
#define SAMPLE_PERS_KEY_ID				PSA_KEY_ID_USER_MIN
#define PRINT_HEX(p_label, p_text, len)\
	({\
		LOG_INF("---- %s (len: %u): ----", p_label, len);\
		LOG_HEXDUMP_INF(p_text, len, "Content:");\
		LOG_INF("---- %s end  ----", p_label);\
	})



static int provision_cert(enum modem_key_mgmt_cred_type type, const uint8_t *data, size_t data_len)
{
    printk("Provisioning certificate type %d...\n", type);
    bool exists;
    modem_key_mgmt_exists(TLS_SEC_TAG, type, &exists);
    if (exists) { 
        printk("Certificate type %d already exists.\n", type);
        return 0;
    }

    printk("Writing certificate type %d...\n", type);
    return modem_key_mgmt_write(TLS_SEC_TAG, type, data, data_len);
}



psa_status_t key_exists(psa_key_id_t key_id)
{
    psa_status_t status;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    status = psa_get_key_attributes(key_id, &attr);
    psa_reset_key_attributes(&attr);

    if (status == PSA_SUCCESS) {
        printk("Key 0x%08x exists.\n", key_id);
    } else if (status == PSA_ERROR_DOES_NOT_EXIST) {
        printk("Key 0x%08x does NOT exist.\n", key_id);
    } else {
        printk("Failed to query key 0x%08x (status: %d)\n", key_id, status);
    }

    return status;
}

int provision_all(void)
{
	int err = 0;

        err = nrf_modem_lib_init();
	if (err) {
                
		return err;
	}

	err = provision_cert(MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, ca_cert, ca_cert_len);
    printk("provision ca_cert: %d\n", err);
    err = provision_cert(MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT, public_cert, public_cert_len);
    printk("provision public_cert: %d\n", err);
    err = provision_cert(MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT, private_key, private_key_len);
    printk("provision private_key: %d\n", err);

	err = provision_config_data();
	if (err) {
		printk("Failed to provision config data: %d\n", err);
	}

	return err;
}


int main(void)
{
        k_sleep(K_MSEC(2000)); // Allow time for system initialization
        printk("TESTING HMAC\n");
        test();
        printk("HMAC test completed.\n");
        k_sleep(K_MSEC(1000)); // Allow time for system initialization
        printk("Starting provisioning...\n");
        provision_all();
        printk("Provisioning finished.\n");
		k_sleep(K_MSEC(1000));
		parse_encrypted_blob();
		

		printf("✅ Parsed %d config entries\n", num_entries);
		for (int i = 0; i < num_entries; i++) {
			printf("Entry %d at 0x%08X: AAD='%.*s', CT len=%d\n",
				i, entries[i].mem_offset,
				entries[i].aad_len, entries[i].aad,
				entries[i].ciphertext_len
			);
		}

	
		k_sleep(K_MSEC(5000)); // Allow time for provisioning to complete
		printk("INIT FOTA");
		fota_init_and_start();
		printk("FOTA initialization complete.\n");
        return 0;
}





