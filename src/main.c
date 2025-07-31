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
// Replace with your secure tag
#define TLS_SEC_TAG 42

// TF-M Protected Storage UID

#define HMAC_KEY_ID ((psa_key_id_t)0x6001)
#define HMAC_KEY_LEN 32


#define CONFIG_BLOB_ADDR1        0x000FB400U
#define CONFIG_BLOB_ADDR2 		0x000FD800U
#define MAX_ENTRIES             64
#define ENTRY_SIZE              128
#define MAX_IV_LEN              12
#define MAX_AAD_LEN             32
#define MAX_CIPHERTEXT_LEN      64
#define BLOB_MAGIC              0x12EFCDAB
#define BLOB_HEADER_SIZE        0

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

int parse_blob_from_flash(size_t max_blob_size, unsigned int blob_add) {
    const uint8_t *blob = (const uint8_t *)blob_add;

    if (!blob || max_blob_size < BLOB_HEADER_SIZE) return -1;

   

    uint16_t entry_count = 10;

    size_t offset = BLOB_HEADER_SIZE;
    for (int i = 0; i < entry_count; i++) {
        if (offset + ENTRY_SIZE > max_blob_size) return -4;

        const uint8_t *entry = &blob[offset];
        size_t pos = 0;

        uint8_t iv_len = entry[pos++];
        if (iv_len > MAX_IV_LEN) return -5;

        ConfigEntry *e = &entries[i];
        e->iv_len = iv_len;
        memcpy(e->iv, &entry[pos], iv_len);
        pos += iv_len;

        e->aad_len = read_u16_le(&entry[pos]);
        pos += 2;
        if (e->aad_len > MAX_AAD_LEN) return -6;
        memcpy(e->aad, &entry[pos], e->aad_len);
        pos += e->aad_len;

        e->ciphertext_len = read_u16_le(&entry[pos]);
        pos += 2;
        if (e->ciphertext_len > MAX_CIPHERTEXT_LEN) return -7;
        memcpy(e->ciphertext, &entry[pos], e->ciphertext_len);
        pos += e->ciphertext_len;

        e->mem_offset = blob_add + offset;

        offset += ENTRY_SIZE;
    }

    num_entries = entry_count;
    return 0;
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

LOG_MODULE_REGISTER(hmac, LOG_LEVEL_DBG);


static int provision_cert(enum modem_key_mgmt_cred_type type, const char *data)
{
        printk("Provisioning certificate type %d...\n", type);
        bool exists;
        modem_key_mgmt_exists(TLS_SEC_TAG, type, &exists);
	if (exists) { 
                printk("Certificate type %d already exists.\n", type);
		return 0;
	}
        printk("Writing certificate type %d...\n", type);
	return modem_key_mgmt_write(TLS_SEC_TAG, type, data, strlen(data));
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

	err = provision_cert(MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN, ca_cert);
	printf("Provisioned CA chain: %d\n", err);

	err = provision_cert(MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT, public_cert);
        printf("Provisioned client certificate: %d\n", err);

	err = provision_cert(MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT, private_key);
        printf("Provisioned private key: %d\n", err);

	err = provision_config_data();
	if (err) {
		printk("Failed to provision config data: %d\n", err);
	}

	return err;
}


int main(void)
{
        k_sleep(K_MSEC(1000)); // Allow time for system initialization
        printk("Starting provisioning...\n");
        provision_all();
        printk("Provisioning finished.\n");
		k_sleep(K_MSEC(1000));
		int res = parse_blob_from_flash(8000,CONFIG_BLOB_ADDR1 );
		if (res != 0) {
			printf("❌ Failed to parse config blob (code %d)\n", res);
			return res;
		}

		printf("✅ Parsed %d config entries\n", num_entries);
		for (int i = 0; i < num_entries; i++) {
			printf("Entry %d at 0x%08X: AAD='%.*s', CT len=%d\n",
				i, entries[i].mem_offset,
				entries[i].aad_len, entries[i].aad,
				entries[i].ciphertext_len
			);
		}
		k_sleep(K_MSEC(1000));
		res = parse_blob_from_flash(8000,CONFIG_BLOB_ADDR2 );
		if (res != 0) {
			printf("❌ Failed to parse config blob (code %d)\n", res);
			return res;
		}

		printf("✅ Parsed %d config entries\n", num_entries);
		for (int i = 0; i < num_entries; i++) {
			printf("Entry %d at 0x%08X: AAD='%.*s', CT len=%d\n",
				i, entries[i].mem_offset,
				entries[i].aad_len, entries[i].aad,
				entries[i].ciphertext_len
			);
		}
		k_sleep(K_MSEC(30000)); // Allow time for provisioning to complete
		printk("INIT FOTA");
		fota_init_and_start();
		printk("FOTA initialization complete.\n");
        return 0;
}
