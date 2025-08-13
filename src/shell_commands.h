#ifndef SHELL_MQTT_H
#define SHELL_MQTT_H

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <psa/protected_storage.h>
#include <psa/crypto.h>
#include <string.h>
#include <tfm_ns_interface.h>







const char *get_config(const char *aad);
void secure_memzero(void *v, size_t n);
void test_decrypt_all_config_entries(void);
int open_persistent_key();
void parse_encrypted_blob(void);
int decrypt_config_field_data(const char *encrypted_data, size_t encrypted_len,
                              const char *iv,
                              const char *additional_data, size_t additional_len,
                              char *output_buf, size_t *output_len);


extern bool s_authed;
extern int64_t s_last_activity_ms;
extern uint8_t  s_fail_count;
extern int64_t  s_lock_until_ms;    

/* Authentication macros */
#define AUTH_TOUCH() \
    do { if (s_authed) { s_last_activity_ms = k_uptime_get(); } } while (0)

#define REQUIRE_AUTH(sh) \
    do { if (!s_authed) { shell_error(sh, "Not authenticated."); return -EPERM; } } while (0)

void secure_memzero(void *v, size_t n);
#endif /* SHELL_MQTT_H */