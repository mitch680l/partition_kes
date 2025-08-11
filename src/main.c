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
#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/init.h>
#include <zephyr/sys/printk.h>
// Replace with your secure tag
#define TLS_SEC_TAG 42

// TF-M Protected Storage UID

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





