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
#include "config.h"
#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/init.h>
#include <zephyr/sys/printk.h>
#include <ctype.h>
#define TLS_SEC_TAG 42



#define PBKDF2_ITERATIONS 64000u

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
#define HMAC_KEY_ID ((psa_key_id_t)0x6001)
#define HMAC_KEY_LEN 32







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

static int hex_nibble(char c){
    if (c>='0'&&c<='9') return c-'0';
    c=(char)tolower((unsigned char)c);
    if (c>='a'&&c<='f') return 10+(c-'a');
    return -1;
}
static bool is_hex(const char* s,size_t n){
    if(n==0||(n&1)) return false;
    for(size_t i=0;i<n;i++){
        char c=s[i];
        if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) return false;
    }
    return true;
}
static bool hex_to_bytes(const char*hex,size_t n,uint8_t*out,size_t*out_len){
    if(!is_hex(hex,n)) return false;
    size_t m=n/2;
    for(size_t i=0;i<m;i++){
        int hi=hex_nibble(hex[2*i]), lo=hex_nibble(hex[2*i+1]);
        if(hi<0||lo<0) return false;
        out[i]=(uint8_t)((hi<<4)|lo);
    }
    *out_len=m; return true;
}

static const ConfigEntry* find_entry(const char* key){
    size_t klen=strlen(key);
    for(int i=0;i<num_entries;i++){
        if(entries[i].aad_len==klen && memcmp(entries[i].aad,key,klen)==0) return &entries[i];
    }
    return NULL;
}

static int derive_pbkdf2_sha256(const uint8_t* pw,size_t pw_len,
                                const uint8_t* salt,size_t salt_len,
                                uint32_t iters,uint8_t*out,size_t out_len){
    psa_status_t st;
    psa_key_derivation_operation_t op=PSA_KEY_DERIVATION_OPERATION_INIT;
    st=psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)); if(st) goto done;
    st=psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, iters); if(st) goto done;
    st=psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len); if(st) goto done;
    st=psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw, pw_len); if(st) goto done;
    st=psa_key_derivation_output_bytes(&op, out, out_len);
done:
    psa_key_derivation_abort(&op);
    return st==PSA_SUCCESS?0:-1;
}









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
        k_sleep(K_MSEC(2000)); 
        printk("TESTING HMAC\n");
        test();
        printk("HMAC test completed.\n");
        k_sleep(K_MSEC(1000));
        printk("Starting provisioning...\n");
        provision_all();
        printk("Provisioning finished.\n");
		k_sleep(K_MSEC(1000));
		parse_encrypted_blob();
        config_init();
		

		printf("Parsed %d config entries\n", num_entries);
		for (int i = 0; i < num_entries; i++) {
			printf("Entry %d at 0x%08X: AAD='%.*s', CT len=%d\n",
				i, entries[i].mem_offset,
				entries[i].aad_len, entries[i].aad,
				entries[i].ciphertext_len
			);
		}

	
		k_sleep(K_MSEC(5000));
        //test_pbkdf2_verify_from_blob_simple();
        k_sleep(K_MSEC(5000 * 1));
		printk("INIT FOTA");
		fota_init_and_start();
		printk("FOTA initialization complete.\n");
        return 0;
}





