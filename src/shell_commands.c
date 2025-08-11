#include "shell_commands.h"
#include <zephyr/sys/crc.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>   
#include <zephyr/random/random.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "config.h"


psa_key_id_t my_key_id = 0x00000005;
psa_key_handle_t my_key_handle;
#define PBKDF2_ITERATIONS 64000u

LOG_MODULE_REGISTER(aes_gcm, LOG_LEVEL_DBG);


#define MAX_TRIES        3
#define LOCKOUT_MS       30000     
#define AUTO_LOGOUT_MS   60000      
#define TEST_PASSWORD    "Password" 
#define PRINT_HEX(label, buf, len)                                      \
    do {                                                                 \
        LOG_INF("---- %s (len: %zu) ----", (label), (size_t)(len));      \
        LOG_HEXDUMP_INF((buf), (len), "Content:");                       \
        LOG_INF("---- %s end ----", (label));                            \
    } while (0)
/* --- state --- */
static uint8_t  s_fail_count;
static int64_t  s_lock_until_ms;    
static int64_t  s_last_activity_ms; 
static bool     s_authed;

static inline int consttime_cmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff;  /* 0 == equal */
}

static inline int derive_pbkdf2_sha256(const uint8_t *pw, size_t pw_len,
                                       const uint8_t *salt, size_t salt_len,
                                       uint32_t iters,
                                       uint8_t *out, size_t out_len)
{
    psa_status_t st;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)); if (st) goto done;
    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, iters); if (st) goto done;
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len); if (st) goto done;
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw, pw_len); if (st) goto done;
    st = psa_key_derivation_output_bytes(&op, out, out_len);
done:
    psa_key_derivation_abort(&op);
    return (st == PSA_SUCCESS) ? 0 : -1;
}

/* Drop-in replacement with hex debug prints */
static inline bool check_password(const char *pw)
{
    if (!pw) return false;

    /* 1) COPY OUT the static results immediately */
    char salt_hex[128];
    char hash_hex[256];

    const char *s_ptr = get_config("pbkdf2.salt");
    if (!s_ptr) return false;
    /* strnlen guard + copy with termination */
    size_t s_len = strnlen(s_ptr, sizeof(salt_hex) - 1);
    memcpy(salt_hex, s_ptr, s_len);
    salt_hex[s_len] = '\0';

    const char *h_ptr = get_config("pbkdf2.hash");
    if (!h_ptr) return false;
    size_t h_len = strnlen(h_ptr, sizeof(hash_hex) - 1);
    memcpy(hash_hex, h_ptr, h_len);
    hash_hex[h_len] = '\0';


    LOG_INF("PBKDF2 iterations: %u", (unsigned)PBKDF2_ITERATIONS);
    LOG_INF("pbkdf2.salt (hex str, raw): %s", salt_hex);
    LOG_INF("pbkdf2.hash (hex str, raw): %s", hash_hex);


    /* 3) Hex -> bytes */
    uint8_t salt[64], hash_ref[64], cand[64];
    size_t salt_len = hex2bin(salt_hex, s_len, salt, sizeof(salt));
    size_t hash_len = hex2bin(hash_hex, h_len, hash_ref, sizeof(hash_ref));
    if (salt_len == 0 || hash_len == 0 || hash_len > sizeof(cand)) return false;

    PRINT_HEX("Salt (bytes)", salt, salt_len);
    PRINT_HEX("Reference PBKDF2 (bytes)", hash_ref, hash_len);

    /* 4) Derive & compare */
    if (derive_pbkdf2_sha256((const uint8_t *)pw, strlen(pw),
                             salt, salt_len, PBKDF2_ITERATIONS,
                             cand, hash_len) != 0) {
        return false;
    }
    PRINT_HEX("Derived PBKDF2 (bytes)", cand, hash_len);

    bool ok = (consttime_cmp(cand, hash_ref, hash_len) == 0);
    memset(cand, 0, hash_len);
    return ok;
}


#define REQUIRE_AUTH(sh) \
    do { if (!s_authed) { shell_error(sh, "Not authenticated."); return -EPERM; } } while (0)


#define AUTH_TOUCH() \
    do { if (s_authed) { s_last_activity_ms = k_uptime_get(); } } while (0)

static inline void set_locked_state(const struct shell *sh)
{
    s_authed = false;
    shell_obscure_set(sh, true);               
    shell_prompt_change(sh, "login> ");         
}

static inline void set_unlocked_state(const struct shell *sh)
{
    s_authed = true;
    s_fail_count = 0;
    s_lock_until_ms = 0;
    shell_obscure_set(sh, false);
    shell_prompt_change(sh, "dev> ");
    s_last_activity_ms = k_uptime_get();
}


static int cmd_login(const struct shell *sh, size_t argc, char **argv)
{
    const int64_t now = k_uptime_get();

    if (s_authed) {
        shell_print(sh, "Already authenticated.");
        return 0;
    }

    if (now < s_lock_until_ms) {
        const int32_t left = (int32_t)(s_lock_until_ms - now);
        shell_warn(sh, "Locked. Try again in %d.%03ds", left/1000, left%1000);
        return -EAGAIN;
    }

    if (argc < 2) {
        shell_print(sh, "Usage: login <password>");
        return -EINVAL;
    }

    if (check_password(argv[1])) {
        shell_print(sh, "OK");
        set_unlocked_state(sh);
        return 0;
    }

    s_fail_count++;
    if (s_fail_count >= MAX_TRIES) {
        s_lock_until_ms = now + LOCKOUT_MS;
        s_fail_count = 0;
        shell_error(sh, "Bad password. Locked for %d s.", LOCKOUT_MS/1000);
    } else {
        shell_error(sh, "Bad password. %u/%u attempt(s) used.", s_fail_count, MAX_TRIES);
    }
    return -EPERM;
}

static int cmd_logout(const struct shell *sh, size_t argc, char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    set_locked_state(sh);
    shell_print(sh, "Logged out.");
    return 0;
}


static void auto_logout_thread(void)
{
    const struct shell *sh = shell_backend_uart_get_ptr();
    while (1) {
        k_sleep(K_SECONDS(1));
        if (s_authed) {
            int64_t now = k_uptime_get();
            if (now - s_last_activity_ms >= AUTO_LOGOUT_MS) {
                set_locked_state(sh);
                shell_warn(sh, "Auto-logout after %d s inactivity", AUTO_LOGOUT_MS/1000);
            }
        }
    }
}
K_THREAD_DEFINE(auto_logout_tid, 1024, auto_logout_thread, NULL, NULL, NULL,
                K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);


static int shell_lockdown_init(void)
{
    s_fail_count = 0;
    s_lock_until_ms = 0;
    s_last_activity_ms = 0;
    s_authed = false;
    return 0;
}
SYS_INIT(shell_lockdown_init, APPLICATION, 50);


typedef struct {
    uint8_t iv[MAX_IV_LEN];
    uint8_t iv_len;
    uint8_t aad[MAX_AAD_LEN];
    uint16_t aad_len;
    uint8_t ciphertext[MAX_CIPHERTEXT_LEN];
    uint16_t ciphertext_len;
    uint32_t mem_offset;
} ConfigEntry;

static ConfigEntry entries[MAX_ENTRIES];
static int num_entries = 0;

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

/* ====================== Shell command impls (with auth touch/guards) ====================== */

static int cmd_parse_blob(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    AUTH_TOUCH();

    shell_print(shell, "Parsing encrypted blob...");
    parse_encrypted_blob();
    shell_print(shell, "Done parsing.");
    return 0;
}

void secure_memzero(void *v, size_t n)
{
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) { *p++ = 0; }
}

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

    LOG_INF("Decrypting config field...");

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

    LOG_INF("Field decryption successful (length: %u)", *output_len);
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

void test_decrypt_all_config_entries(void)
{
    char decrypted[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
    size_t decrypted_len;

    LOG_INF("Starting config entry decryption test...");

    for (int i = 0; i < num_entries; i++) {
        const ConfigEntry *e = &entries[i];
        k_sleep(K_MSEC(100));
        LOG_INF("Decrypting entry %d: AAD length=%d, Ciphertext length=%d", 
                i, e->aad_len, e->ciphertext_len);

        int ret = decrypt_config_field_data(
            (const char *)e->ciphertext, e->ciphertext_len,
            (const char *)e->iv,
            (const char *)e->aad, e->aad_len,
            decrypted, &decrypted_len
        );

        if (ret != PROVISIONING_SUCCESS) {
            LOG_ERR("Failed to decrypt entry %d", i);
            continue;
        }

        if (decrypted_len < sizeof(decrypted)) {
            decrypted[decrypted_len] = '\0';
        } else {
            decrypted[sizeof(decrypted) - 1] = '\0';
        }

        LOG_INF("Decrypted entry %d: %s", i, decrypted);
    }

    LOG_INF("Config entry decryption test complete.");
}

static int update_crc(void)
{
    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        LOG_ERR("flash_area_open for CRC failed: %d", err);
        return err;
    }

    uint32_t new_crc = manual_crc32(ENCRYPTED_BLOB_ADDR, ENCRYPTED_BLOB_SIZE - 4);
    uint32_t crc_offset = CRC_LOCATION_OFFSET;
    uint32_t page_start = (crc_offset / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;

    static uint8_t page_buf[FLASH_PAGE_SIZE];

    err = flash_area_read(fa, page_start, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_read for CRC page failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    uint32_t crc_offset_in_page = crc_offset - page_start;
    memcpy(&page_buf[crc_offset_in_page], &new_crc, 4);

    err = flash_area_erase(fa, page_start, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_erase CRC page failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    err = flash_area_write(fa, page_start, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("CRC write failed: %d", err);
    } else {
        LOG_INF("CRC updated: 0x%08X at offset 0x%x", new_crc, crc_offset);
    }

    flash_area_close(fa);
    return err;
}

/* ---------- Shell handlers (write/erase guarded) ---------- */

static int cmd_crc_update(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();
    REQUIRE_AUTH(shell);

    if (argc != 2 || strcmp(argv[1], "update") != 0) {
        shell_error(shell, "Usage: cfg crc update");
        return -EINVAL;
    }

    int ret = update_crc();
    if (ret == 0) {
        shell_print(shell, "CRC update completed successfully.");
    } else {
        shell_error(shell, "CRC update failed: %d", ret);
    }

    return ret;
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

static int update_single_entry(int index, const uint8_t *new_data, size_t data_len)
{
    if (index < 0 || index >= TOTAL_ENTRIES) {
        LOG_ERR("Invalid entry index %d (max: %d)", index, TOTAL_ENTRIES - 1);
        return -EINVAL;
    }
    
    size_t entry_offset = index * ENTRY_SIZE;
    
    if (entry_offset + ENTRY_SIZE > CRC_LOCATION_OFFSET) {
        LOG_ERR("Entry %d would overwrite CRC location", index);
        return -EINVAL;
    }

    int page_index = index / ENTRIES_PER_PAGE;
    int entry_in_page = index % ENTRIES_PER_PAGE;
    
    size_t page_offset = page_index * FLASH_PAGE_SIZE;
    uint8_t page_buf[FLASH_PAGE_SIZE];

    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        LOG_ERR("flash_area_open failed: %d", err);
        return err;
    }

    err = flash_area_read(fa, page_offset, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_read failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    size_t entry_offset_in_page = entry_in_page * ENTRY_SIZE;
    memcpy(&page_buf[entry_offset_in_page], new_data, ENTRY_SIZE);

    err = flash_area_erase(fa, page_offset, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_erase failed: %d (offset: 0x%x)", err, (unsigned int)page_offset);
        flash_area_close(fa);
        return err;
    }

    err = flash_area_write(fa, page_offset, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_write failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    flash_area_close(fa);
    LOG_INF("Updated entry %d in page %d (4KB-aligned)", index, page_index);
    return update_crc();
}

const char *get_config(const char *aad)
{
    static char decrypted[DECRYPTED_OUTPUT_MAX]; // persistent output
    size_t decrypted_len = 0;

    for (int i = 0; i < num_entries; i++) {
        ConfigEntry *e = &entries[i];

        if (e->aad_len == strlen(aad) &&
            memcmp(e->aad, aad, e->aad_len) == 0) {

            int ret = decrypt_config_field_data(
                (const char *)e->ciphertext, e->ciphertext_len,
                (const char *)e->iv,
                (const char *)e->aad, e->aad_len,
                decrypted, &decrypted_len
            );

            if (ret != 0) {
                LOG_ERR("Decryption failed for AAD: %s", aad);
                return NULL;
            }

            decrypted[decrypted_len] = '\0'; // null-terminate
            return decrypted;
        }
    }

    LOG_WRN("AAD not found: %s", aad);
    return "NULL";
}

/* ---------- read/inspect commands (no auth required) ---------- */

static int cmd_get_config(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();

    if (argc != 2) {
        shell_error(shell, "Usage: cfg get_config <aad>");
        return -EINVAL;
    }

    const char *aad = argv[1];
    const char *value = get_config(aad);

    if (!value) {
        shell_error(shell, "No entry found or decryption failed for AAD: %s", aad);
        return -ENOENT;
    }

    shell_print(shell, "%s = %s", aad, value);
    return 0;
}

static int overwrite_config_page(int page_index, const uint8_t *page_data)
{
    if (page_index < 1 || page_index > CONFIG_PAGE_COUNT) {
        LOG_ERR("Invalid page index %d (valid: 1-%d)", page_index, CONFIG_PAGE_COUNT);
        return -EINVAL;
    }

    size_t page_offset = (page_index - 1) * FLASH_PAGE_SIZE;

    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        LOG_ERR("flash_area_open failed: %d", err);
        return err;
    }

    err = flash_area_erase(fa, page_offset, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_erase failed: %d (offset: 0x%x)", err, (unsigned int)page_offset);
        flash_area_close(fa);
        return err;
    }

    err = flash_area_write(fa, page_offset, page_data, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_write failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    flash_area_close(fa);
    LOG_INF("Overwrote page %d at offset 0x%x", page_index, (unsigned int)page_offset);

    /* keep CRC valid after any page write */
    return update_crc();
}

static int cmd_set_page(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();
    REQUIRE_AUTH(shell);

    if (argc < 2) {
        shell_error(shell, "Usage: cfg set_page <page:1-2> [aad1 data1] [aad2 data2] ...");
        return -EINVAL;
    }

    int page = atoi(argv[1]);
    if (page < 1 || page > CONFIG_PAGE_COUNT) {
        shell_error(shell, "Invalid page index %d", page);
        return -EINVAL;
    }

    uint8_t page_buf[FLASH_PAGE_SIZE];
    memset(page_buf, 0xFF, FLASH_PAGE_SIZE);

    int entry_index = 0;
    int arg_index = 2;

    while (entry_index < ENTRIES_PER_PAGE && (arg_index + 1) < argc) {
        size_t entry_offset = ((page - 1) * FLASH_PAGE_SIZE) + (entry_index * ENTRY_SIZE);

        bool overlaps_crc = (entry_offset < CRC_LOCATION_OFFSET) &&
                            (entry_offset + ENTRY_SIZE > CRC_LOCATION_OFFSET);

        const char *aad = argv[arg_index];
        const char *data = argv[arg_index + 1];
        arg_index += 2;

        if (overlaps_crc || strlen(aad) == 0 || strlen(data) == 0) {
            memset(&page_buf[entry_index * ENTRY_SIZE], 0xFF, ENTRY_SIZE);
            entry_index++;
            continue;
        }

        uint8_t encrypted_entry[ENTRY_SIZE];
        int ret = create_encrypted_entry_with_aad(aad, data, encrypted_entry);
        if (ret != 0) {
            shell_error(shell, "Failed to encrypt entry %d: %d", entry_index, ret);
            return ret;
        }

        memcpy(&page_buf[entry_index * ENTRY_SIZE], encrypted_entry, ENTRY_SIZE);
        entry_index++;
    }

    while (entry_index < ENTRIES_PER_PAGE) {
        memset(&page_buf[entry_index * ENTRY_SIZE], 0xFF, ENTRY_SIZE);
        entry_index++;
    }

    shell_print(shell, "Writing page %d with %d entries", page, ENTRIES_PER_PAGE);
    return overwrite_config_page(page, page_buf);
}

static int cmd_set_entry(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();
    REQUIRE_AUTH(shell);

    if (argc != 3) {
        shell_error(shell, "Usage: cfg set <aad> <data>");
        return -EINVAL;
    }

    const char *aad = argv[1];
    const char *data = argv[2];

    uint8_t encrypted_entry[ENTRY_SIZE];
    int ret = create_encrypted_entry_with_aad(aad, data, encrypted_entry);
    if (ret != 0) {
        shell_error(shell, "Failed to create encrypted entry: %d", ret);
        return ret;
    }

    int selected_index = -1;
    for (int i = 0; i < TOTAL_ENTRIES; i++) {
        size_t entry_offset = i * ENTRY_SIZE;

        if (entry_offset + ENTRY_SIZE > CRC_LOCATION_OFFSET)
            continue;

        const uint8_t *entry_ptr = ENCRYPTED_BLOB_ADDR + entry_offset;
        if (entry_ptr[0] == 0xFF) {
            if (selected_index == -1)
                selected_index = i;
            continue;
        }

        uint8_t iv_len = entry_ptr[0];
        const uint8_t *aad_len_ptr = entry_ptr + 1 + iv_len;
        uint16_t existing_aad_len = aad_len_ptr[0] | (aad_len_ptr[1] << 8);
        const char *existing_aad = (const char *)(aad_len_ptr + 2);

        if (existing_aad_len == strlen(aad) && memcmp(existing_aad, aad, existing_aad_len) == 0) {
            selected_index = i;
            break;
        }
    }

    if (selected_index == -1) {
        shell_error(shell, "No free slot and no matching AAD to override");
        return -ENOSPC;
    }

    shell_print(shell, "Writing entry at index %d (AAD: \"%s\")...", selected_index, aad);
    return update_single_entry(selected_index, encrypted_entry, ENTRY_SIZE);
}


static int cmd_get_entry_hex(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();

    if (argc != 2) {
        shell_error(shell, "Usage: cfg get_hex <index>");
        return -EINVAL;
    }

    int index = atoi(argv[1]);
    if (index < 0 || index >= TOTAL_ENTRIES) {
        shell_error(shell, "Invalid index %d (max: %d)", index, TOTAL_ENTRIES - 1);
        return -EINVAL;
    }

    const uint8_t *entry = ENCRYPTED_BLOB_ADDR + index * ENTRY_SIZE;
    shell_print(shell, "Entry %d (hex):", index);
    for (int i = 0; i < ENTRY_SIZE; i++) {
        shell_fprintf(shell, SHELL_NORMAL, "%02X ", entry[i]);
        if ((i + 1) % 16 == 0) {
            shell_print(shell, "");
            k_sleep(K_MSEC(10));
        }
    }
    return 0;
}

static int cmd_get_page_hex(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();

    if (argc != 2) {
        shell_error(shell, "Usage: cfg get_page_hex <page_index:1-2>");
        return -EINVAL;
    }

    int page_index = atoi(argv[1]);
    if (page_index < 1 || page_index > CONFIG_PAGE_COUNT) {
        shell_error(shell, "Invalid page index %d (valid: 1-%d)", page_index, CONFIG_PAGE_COUNT);
        return -EINVAL;
    }

    const uint8_t *page = ENCRYPTED_BLOB_ADDR + (page_index - 1) * FLASH_PAGE_SIZE;
    shell_print(shell, "Page %d (hex):", page_index);
    for (int i = 0; i < FLASH_PAGE_SIZE; i++) {
        shell_fprintf(shell, SHELL_NORMAL, "%02X ", page[i]);
        if ((i + 1) % 16 == 0) {
            shell_print(shell, "");
            k_sleep(K_MSEC(5));
        }
    }
    return 0;
}

static int cmd_get_blob_hex(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();

    shell_print(shell, "Full blob (size: %d, CRC at offset 0x%x):", ENCRYPTED_BLOB_SIZE, CRC_LOCATION_OFFSET);
    for (int i = 0; i < ENCRYPTED_BLOB_SIZE; i++) {
        shell_fprintf(shell, SHELL_NORMAL, "%02X ", ENCRYPTED_BLOB_ADDR[i]);
        if ((i + 1) % 16 == 0) {
            shell_print(shell, "");
            k_sleep(K_MSEC(5));
        }
    }
    return 0;
}

static int cmd_get_crc_info(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();

    uint32_t computed_crc = manual_crc32(ENCRYPTED_BLOB_ADDR, ENCRYPTED_BLOB_SIZE - 4);
    uint32_t stored_crc = *(uint32_t *)(ENCRYPTED_BLOB_ADDR + CRC_LOCATION_OFFSET);
    
    shell_print(shell, "CRC Information:");
    shell_print(shell, "  Location: 0x%x (last 4 bytes)", CRC_LOCATION_OFFSET);
    shell_print(shell, "  Computed: 0x%08X", computed_crc);
    shell_print(shell, "  Stored:   0x%08X", stored_crc);
    shell_print(shell, "  Status:   %s", (computed_crc == stored_crc) ? "VALID" : "INVALID");
    
    return 0;
}

static int cmd_show_layout(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();

    shell_print(shell, "Encrypted Blob Layout:");
    shell_print(shell, "  Base Address:     0x%x", (unsigned int)ENCRYPTED_BLOB_ADDR);
    shell_print(shell, "  Total Size:       %d bytes (8KB)", ENCRYPTED_BLOB_SIZE);
    shell_print(shell, "  Header Size:      %d bytes", BLOB_HEADER_SIZE);
    shell_print(shell, "  Entry Size:       %d bytes", ENTRY_SIZE);
    shell_print(shell, "  Page Size:        %d bytes (4KB)", FLASH_PAGE_SIZE);
    shell_print(shell, "  Entries per Page: %d", ENTRIES_PER_PAGE);
    shell_print(shell, "  Config Pages:     %d", CONFIG_PAGE_COUNT);
    shell_print(shell, "  Total Entries:    %d", TOTAL_ENTRIES);
    shell_print(shell, "  CRC Location:     0x%x (offset %d)", 
                (unsigned int)(ENCRYPTED_BLOB_ADDR + CRC_LOCATION_OFFSET), CRC_LOCATION_OFFSET);
    
    shell_print(shell, "\nPage Layout:");
    for (int i = 1; i <= CONFIG_PAGE_COUNT; i++) {
        size_t page_offset = (i - 1) * FLASH_PAGE_SIZE;
        int start_entry = (i - 1) * ENTRIES_PER_PAGE;
        int end_entry = start_entry + ENTRIES_PER_PAGE - 1;
        shell_print(shell, "  Page %d: offset 0x%x, entries %d-%d", 
                    i, (unsigned int)page_offset, start_entry, end_entry);
    }
    
    return 0;
}

static int cmd_erase_page(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();
    REQUIRE_AUTH(shell);

    if (argc != 3 || strcmp(argv[1], "page") != 0) {
        shell_error(shell, "Usage: cfg erase page <1|2>");
        return -EINVAL;
    }

    int page = atoi(argv[2]);
    if (page != 1 && page != 2) {
        shell_error(shell, "Invalid page number: %d. Must be 1 or 2.", page);
        return -EINVAL;
    }

    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        shell_error(shell, "flash_area_open failed: %d", err);
        return err;
    }

    off_t offset = (page - 1) * FLASH_PAGE_SIZE;

    err = flash_area_erase(fa, offset, FLASH_PAGE_SIZE);
    if (err) {
        shell_error(shell, "Failed to erase page %d: %d", page, err);
    } else {
        shell_print(shell, "Erased page %d at offset 0x%08x", page, (uint32_t)offset);
    }

    flash_area_close(fa);
    return err;
}

void get_all_config_entries(const struct shell *shell)
{
    char decrypted[DECRYPTED_OUTPUT_MAX];
    size_t decrypted_len = 0;

    for (int i = 0; i < num_entries; i++) {
        ConfigEntry *e = &entries[i];

        int ret = decrypt_config_field_data(
            (const char *)e->ciphertext, e->ciphertext_len,
            (const char *)e->iv,
            (const char *)e->aad, e->aad_len,
            decrypted, &decrypted_len
        );

        if (ret != 0) {
            shell_error(shell, "Failed to decrypt entry %d (AAD: %.*s)", i, e->aad_len, e->aad);
            continue;
        }

        decrypted[decrypted_len] = '\0';
        shell_print(shell, "%.*s = %s", e->aad_len, e->aad, decrypted);
    }
}

static int cmd_get_all(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    AUTH_TOUCH();
    
    shell_print(shell, "All configuration entries:");
    get_all_config_entries(shell);
    return 0;
}

/* ====================== Command group: cfg ====================== */
static int cmd_cfg_help(const struct shell *shell, size_t argc, char **argv);

SHELL_STATIC_SUBCMD_SET_CREATE(cfg_crc_cmds,
    SHELL_CMD_ARG(update, NULL, "Recompute/write CRC (auth required)", cmd_crc_update, 2, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(cfg_cmds,
    SHELL_CMD(parse,       NULL, "Parse encrypted blob into RAM index",           cmd_parse_blob),
    SHELL_CMD_ARG(get_config, NULL, "Decrypt value by AAD: cfg get_config <aad>", cmd_get_config, 2, 0),
    SHELL_CMD(get_all,     NULL, "List all AAD=value pairs",                      cmd_get_all),
    SHELL_CMD_ARG(set,     NULL, "Set/override entry (auth): cfg set <aad> <data>", cmd_set_entry, 3, 0),
    SHELL_CMD_ARG(set_page,NULL, "Write a full page (auth): cfg set_page <1|2> [aad data] ...", cmd_set_page, 3, ENTRIES_PER_PAGE*2),
    SHELL_CMD_ARG(get_hex, NULL, "Hex dump entry: cfg get_hex <index>",           cmd_get_entry_hex, 2, 0),
    SHELL_CMD_ARG(get_page_hex, NULL, "Hex dump page: cfg get_page_hex <1|2>",    cmd_get_page_hex, 2, 0),
    SHELL_CMD(get_blob_hex,NULL, "Hex dump entire blob",                          cmd_get_blob_hex),
    SHELL_CMD(get_crc,    NULL,  "Show CRC info",                                 cmd_get_crc_info),
    SHELL_CMD(show_layout,NULL,  "Show memory layout",                            cmd_show_layout),
    SHELL_CMD(erase,      NULL,  "Erase ops: cfg erase page <1|2> (auth)",        cmd_erase_page),
    SHELL_CMD(crc, &cfg_crc_cmds, "CRC operations: cfg crc update",               NULL),
    SHELL_CMD(help,       NULL,  "Show this help",                                 cmd_cfg_help),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(cfg, &cfg_cmds, "Config blob commands", NULL);


SHELL_CMD_REGISTER(login,  NULL, "Authenticate: login <password>",  cmd_login);
SHELL_CMD_REGISTER(logout, NULL, "Logout and re-lock the shell",     cmd_logout);

static int cmd_cfg_help(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    shell_print(shell,
        "cfg commands:\n"
        "  parse                         Parse encrypted blob into RAM index\n"
        "  get_config <aad>              Decrypt and print value by AAD\n"
        "  get_all                       Print all AAD=value pairs\n"
        "  set <aad> <data>              Create/override entry (auth)\n"
        "  set_page <1|2> [aad data]...  Create a full page image (auth)\n"
        "  get_hex <index>               Dump one entry in hex\n"
        "  get_page_hex <1|2>            Dump a page in hex\n"
        "  get_blob_hex                  Dump entire blob in hex\n"
        "  get_crc                       Show CRC information\n"
        "  crc update                    Recompute/write CRC (auth)\n"
        "  show_layout                   Show blob memory layout\n"
        "  erase page <1|2>              Erase page (auth)\n"
        "\nAuth:\n"
        "  login <password>              Authenticate (default: \"" TEST_PASSWORD "\")\n"
        "  logout                        Re-lock the shell\n"
        "\nNotes:\n"
        "  - Logs are always available.\n"
        "  - Auto-logout after %d s inactivity; lockout %d s after %d bad tries.\n",
        (int)(AUTO_LOGOUT_MS/1000), (int)(LOCKOUT_MS/1000), (int)MAX_TRIES);
    return 0;
}







