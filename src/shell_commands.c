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
#include "encryption_helper.h"
#include "config.h"





LOG_MODULE_REGISTER(aes_gcm, LOG_LEVEL_DBG);



#define PRINT_HEX(label, buf, len)                                      \
    do {                                                                 \
        LOG_INF("---- %s (len: %zu) ----", (label), (size_t)(len));      \
        LOG_HEXDUMP_INF((buf), (len), "Content:");                       \
        LOG_INF("---- %s end ----", (label));                            \
    } while (0)
/* --- state --- */

uint8_t  s_fail_count;

int64_t  s_lock_until_ms;    

int64_t  s_last_activity_ms; 
bool     s_authed;

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




    /* 3) Hex -> bytes */
    uint8_t salt[64], hash_ref[64], cand[64];
    size_t salt_len = hex2bin(salt_hex, s_len, salt, sizeof(salt));
    size_t hash_len = hex2bin(hash_hex, h_len, hash_ref, sizeof(hash_ref));
    if (salt_len == 0 || hash_len == 0 || hash_len > sizeof(cand)) return false;


    /* 4) Derive & compare */
    if (derive_pbkdf2_sha256((const uint8_t *)pw, strlen(pw),
                             salt, salt_len, PBKDF2_ITERATIONS,
                             cand, hash_len) != 0) {
        return false;
    }


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
    REQUIRE_AUTH(sh);
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








/* ====================== Shell command impls (with auth touch/guards) ====================== */

static int cmd_parse_blob(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    AUTH_TOUCH();
    REQUIRE_AUTH(shell);

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

static int erase_entry_by_aad(const char *aad)
{
    if (!aad) {
        LOG_ERR("AAD is NULL");
        return -EINVAL;
    }

    /* Search entries[] for matching AAD */
    int found_index = -1;
    for (int i = 0; i < num_entries; i++) {
        if (entries[i].aad_len == strlen(aad) &&
            memcmp(entries[i].aad, aad, entries[i].aad_len) == 0) {
            found_index = i;
            break;
        }
    }

    if (found_index < 0) {
        LOG_WRN("No entry found for AAD '%s'", aad);
        return -ENOENT;
    }

    LOG_INF("Erasing entry %d (AAD='%s')", found_index, aad);

    /* Page & entry calculations */
    size_t entry_offset = (size_t)found_index * ENTRY_SIZE;
    if (entry_offset + ENTRY_SIZE > CRC_LOCATION_OFFSET) {
        LOG_ERR("Entry %d would overwrite CRC location", found_index);
        return -EINVAL;
    }

    int page_index = found_index / ENTRIES_PER_PAGE;
    int entry_in_page = found_index % ENTRIES_PER_PAGE;
    size_t page_offset = page_index * FLASH_PAGE_SIZE;

    uint8_t page_buf[FLASH_PAGE_SIZE];

    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        LOG_ERR("flash_area_open failed: %d", err);
        return err;
    }

    /* Read the whole page */
    err = flash_area_read(fa, page_offset, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_read failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    /* Fill the entry with 0xFF (or 0x00 depending on your "empty" definition) */
    size_t entry_offset_in_page = entry_in_page * ENTRY_SIZE;
    memset(&page_buf[entry_offset_in_page], 0xFF, ENTRY_SIZE);

    /* Erase the page */
    err = flash_area_erase(fa, page_offset, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_erase failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    /* Write the modified page back */
    err = flash_area_write(fa, page_offset, page_buf, FLASH_PAGE_SIZE);
    if (err) {
        LOG_ERR("flash_area_write failed: %d", err);
        flash_area_close(fa);
        return err;
    }

    flash_area_close(fa);

    LOG_INF("Erased entry %d in page %d (4KB-aligned)", found_index, page_index);

    /* Recalculate CRC */
    return update_crc();
}
static int cmd_erase_entry(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();
    REQUIRE_AUTH(shell);

    if (argc != 2) {
        shell_print(shell, "Usage: erase_entry <aad>");
        return -EINVAL;
    }

    const char *aad = argv[1];
    int ret = erase_entry_by_aad(aad);

    if (ret == 0) {
        shell_print(shell, "Entry with AAD '%s' erased successfully", aad);
    } else if (ret == -ENOENT) {
        shell_error(shell, "No entry found with AAD '%s'", aad);
    } else {
        shell_error(shell, "Erase failed (err %d)", ret);
    }

    return ret;
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



/* ---------- read/inspect commands (no auth required) ---------- */

static int cmd_get_config(const struct shell *shell, size_t argc, char **argv)
{
    AUTH_TOUCH();
    REQUIRE_AUTH(shell);

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
    REQUIRE_AUTH(shell);

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
    REQUIRE_AUTH(shell);

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
    REQUIRE_AUTH(shell);

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
    REQUIRE_AUTH(shell);

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
    REQUIRE_AUTH(shell);

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
    REQUIRE_AUTH(shell);
    
    shell_print(shell, "All configuration entries:");
    get_all_config_entries(shell);
    return 0;
}




/* Pack entries[] sequentially into the blob body, page-by-page, using STACK buffer.
 * - Entries are written at offsets: 0, 128, 256, ...
 * - Each entry region is zero-padded to ENTRY_SIZE bytes.
 * - Everything else is filled with 0xFF.
 * - We only touch [0, CRC_LOCATION_OFFSET); CRC trailer is NOT written here.
 * Call update_crc() after this returns 0.
 */
static int rebuild_blob_compact_from_entries_stack(void)
{
    const size_t body_len = CRC_LOCATION_OFFSET;    /* exclude CRC */
    const struct flash_area *fa;
    int err = flash_area_open(FLASH_AREA_ID(encrypted_blob_slot0), &fa);
    if (err) {
        LOG_ERR("flash_area_open: %d", err);
        return err;
    }

    /* Next entry to place and next absolute offset to write it to */
    int next_idx = 0;
    size_t next_off = 0;

    for (size_t page_off = 0; page_off < body_len; page_off += FLASH_PAGE_SIZE) {
        /* Portion of this page that belongs to the body (last page may be partial) */
        size_t write_len = body_len - page_off;
        if (write_len > FLASH_PAGE_SIZE) write_len = FLASH_PAGE_SIZE;

        /* One page buffer on STACK */
        uint8_t page_buf[FLASH_PAGE_SIZE];

        /* Default page contents (outside body range) are irrelevant; we fill the body portion: */
        memset(page_buf, 0xFF, sizeof(page_buf));

        /* Fill as many sequential entries as fit into this page slice */
        while (next_idx < num_entries) {
            const ConfigEntry *e = &entries[next_idx];

            /* Sanity on this entry */
            if (e->iv_len == 0 || e->iv_len > MAX_IV_LEN ||
                e->aad_len == 0 || e->aad_len > MAX_AAD_LEN ||
                e->ciphertext_len == 0 || e->ciphertext_len > MAX_CIPHERTEXT_LEN) {
                LOG_WRN("Skipping invalid entry %d (iv=%u,aad=%u,ct=%u)",
                        next_idx, e->iv_len, e->aad_len, e->ciphertext_len);
                next_idx++;
                continue;
            }

            /* If the next entry doesn't start inside this page slice, break to write the page */
            if (next_off < page_off || (next_off >= page_off + write_len)) {
                break;
            }

            /* Ensure the whole entry fits within this page slice */
            if (next_off + ENTRY_SIZE > page_off + write_len) {
                break; /* write remaining part in the next page iteration */
            }

            /* Serialize entry at its compacted position (next_off) */
            size_t off_in_page = next_off - page_off;
            uint8_t *p   = &page_buf[off_in_page];
            uint8_t *end = p + ENTRY_SIZE;

            /* Zero-pad entire 128-byte entry region */
            memset(p, 0x00, ENTRY_SIZE);

            /* iv_len (1) */
            *p++ = e->iv_len;

            /* iv */
            if (p + e->iv_len > end) { LOG_WRN("Entry %d overflow (iv)", next_idx); goto advance; }
            memcpy(p, e->iv, e->iv_len);
            p += e->iv_len;

            /* aad_len (LE16) */
            if (p + 2 > end) { LOG_WRN("Entry %d overflow (aad_len)", next_idx); goto advance; }
            p[0] = (uint8_t)(e->aad_len & 0xFF);
            p[1] = (uint8_t)((e->aad_len >> 8) & 0xFF);
            p += 2;

            /* aad */
            if (p + e->aad_len > end) { LOG_WRN("Entry %d overflow (aad)", next_idx); goto advance; }
            memcpy(p, e->aad, e->aad_len);
            p += e->aad_len;

            /* ciphertext_len (LE16) */
            if (p + 2 > end) { LOG_WRN("Entry %d overflow (ct_len)", next_idx); goto advance; }
            p[0] = (uint8_t)(e->ciphertext_len & 0xFF);
            p[1] = (uint8_t)((e->ciphertext_len >> 8) & 0xFF);
            p += 2;

            /* ciphertext (ct||tag) */
            if (p + e->ciphertext_len > end) { LOG_WRN("Entry %d overflow (ct)", next_idx); goto advance; }
            memcpy(p, e->ciphertext, e->ciphertext_len);
            p += e->ciphertext_len;

advance:
            /* Advance to the next compact slot regardless; this entry region is zero-padded already */
            next_idx++;
            next_off += ENTRY_SIZE;
        }

        /* Erase + write the page slice */
        err = flash_area_erase(fa, page_off, FLASH_PAGE_SIZE);
        if (err) {
            LOG_ERR("erase @0x%x: %d", (unsigned)page_off, err);
            flash_area_close(fa);
            return err;
        }

        /* Write only the valid portion of this page that belongs to body_len */
        err = flash_area_write(fa, page_off, page_buf, write_len);
        if (err) {
            LOG_ERR("write @0x%x: %d", (unsigned)page_off, err);
            flash_area_close(fa);
            return err;
        }

        /* If we’ve placed all entries and filled all compacted slots, keep looping to finish
           erasing/writing any remaining body bytes as 0xFF (already in page_buf). */
    }

    flash_area_close(fa);

    /* Done packing the payload; CRC still needs to be updated */
    LOG_INF("Compacted %d entries into blob (0..0x%zx), CRC untouched",
            next_idx, (size_t)(CRC_LOCATION_OFFSET - 1));
    return 0;
}
int rebuild_and_update_crc(void)
{
    int rc = rebuild_blob_compact_from_entries_stack();
    if (rc) return rc;
    return update_crc();  /* writes CRC at CRC_LOCATION_OFFSET */
}
static int cmd_rebuild_blob(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
    AUTH_TOUCH();
    REQUIRE_AUTH(shell);

    shell_print(shell, "Rebuilding blob from entries[] (compacted layout)...");
    int rc = rebuild_blob_compact_from_entries_stack();
    if (rc) {
        shell_error(shell, "Blob rebuild failed: %d", rc);
        return rc;
    }

    rc = update_crc();
    if (rc) {
        shell_error(shell, "CRC update failed: %d", rc);
        return rc;
    }

    shell_print(shell, "Blob rebuilt and CRC updated successfully");
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
    SHELL_CMD(erase_entry, NULL, "Erase entry by AAD: cfg erase_entry <aad> (auth)", cmd_erase_entry),
    SHELL_CMD(crc, &cfg_crc_cmds, "CRC operations: cfg crc update",               NULL),
    SHELL_CMD(rebuild_blob, NULL, "Rebuild blob from entries[] (compacted layout)", cmd_rebuild_blob),
    SHELL_CMD(help,       NULL,  "Show this help",                                 cmd_cfg_help),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(cfg, &cfg_cmds, "Config blob commands", NULL);


SHELL_CMD_REGISTER(login,  NULL, "Authenticate: login <password>",  cmd_login);
SHELL_CMD_REGISTER(logout, NULL, "Logout and re-lock the shell",     cmd_logout);

static int cmd_cfg_help(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    AUTH_TOUCH();
    REQUIRE_AUTH(shell);
    
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
        "  rebuild_blob                Rebuild blob from entries[] (compacted layout)\n"
        "  erase_entry <aad>             Erase entry by AAD (auth)\n"
        "  erase page <1|2>              Erase page (auth)\n"
        "\nAuth:\n"
        "  login <password>              Authenticate \n"
        "  logout                        Re-lock the shell\n"
        "\nNotes:\n"
        "  - Logs are always available.\n"
        "  - Auto-logout after %d s inactivity; lockout %d s after %d bad tries.\n",
        (int)(AUTO_LOGOUT_MS/1000), (int)(LOCKOUT_MS/1000), (int)MAX_TRIES);
    return 0;
}








/*
 * Backup shell: copy 8KB encrypted blob between two slots.
 *
 * Requires two flash partitions/areas:
 *   - encrypted_blob_slot0  (e.g. address 0x000FB000, size 0x2000)
 *   - encrypted_blob_slot1  (e.g. address 0x000FE000, size 0x2000)
 *
 * Example usage:
 *   uart:~$ backup copyinto 0 1    # copy slot0 -> slot1
 */



/* Slot constants per your description */
#define BLOB_SLOT_SIZE_BYTES   (8 * 1024)    /* 8 KB total per slot */
#define ERASE_STEP_BYTES       (4 * 1024)    /* driver erases 4 KB at a time */

/* Read/Write buffer chunk. Keep modest to fit small stacks. */
#define COPY_CHUNK_BYTES       256


static int slot_to_area_id(int slot, uint8_t *out_area_id)
{
    if (slot == 0) {
        *out_area_id = FLASH_AREA_ID(encrypted_blob_slot0);
        return 0;
    } else if (slot == 1) {
        *out_area_id = FLASH_AREA_ID(encrypted_blob_slot1);
        return 0;
    }
    return -EINVAL;
}

static int erase_slot(const struct flash_area *fa)
{
    /* Erase exactly 8KB in 4KB steps from offset 0 */
    for (size_t off = 0; off < BLOB_SLOT_SIZE_BYTES; off += ERASE_STEP_BYTES) {
        int err = flash_area_erase(fa, off, ERASE_STEP_BYTES);
        if (err) {
            LOG_ERR("Erase failed at off=0x%zx err=%d", off, err);
            return err;
        }
    }
    return 0;
}

static int copy_slot(int src_slot, int dst_slot)
{
    if (src_slot == dst_slot) {
        LOG_ERR("Source and destination slots are identical");
        return -EINVAL;
    }

    uint8_t src_id, dst_id;
    int err = slot_to_area_id(src_slot, &src_id);
    if (err) {
        LOG_ERR("Invalid src slot %d", src_slot);
        return err;
    }
    err = slot_to_area_id(dst_slot, &dst_id);
    if (err) {
        LOG_ERR("Invalid dst slot %d", dst_slot);
        return err;
    }

    const struct flash_area *src_fa = NULL, *dst_fa = NULL;
    err = flash_area_open(src_id, &src_fa);
    if (err) {
        LOG_ERR("flash_area_open(src) failed: %d", err);
        return err;
    }
    err = flash_area_open(dst_id, &dst_fa);
    if (err) {
        LOG_ERR("flash_area_open(dst) failed: %d", err);
        flash_area_close(src_fa);
        return err;
    }

   

    /* Erase destination slot */
    err = erase_slot(dst_fa);
    if (err) {
        goto out_close;
    }

    /* Copy in small chunks */
    uint8_t buf[COPY_CHUNK_BYTES];
    for (size_t off = 0; off < BLOB_SLOT_SIZE_BYTES; off += COPY_CHUNK_BYTES) {
        size_t chunk = MIN(COPY_CHUNK_BYTES, BLOB_SLOT_SIZE_BYTES - off);

        err = flash_area_read(src_fa, off, buf, chunk);
        if (err) {
            LOG_ERR("Read src failed off=0x%zx err=%d", off, err);
            goto out_close;
        }

        err = flash_area_write(dst_fa, off, buf, chunk);
        if (err) {
            LOG_ERR("Write dst failed off=0x%zx err=%d", off, err);
            goto out_close;
        }
    }

    /* Verify write */
    for (size_t off = 0; off < BLOB_SLOT_SIZE_BYTES; off += COPY_CHUNK_BYTES) {
        size_t chunk = MIN(COPY_CHUNK_BYTES, BLOB_SLOT_SIZE_BYTES - off);

        uint8_t src_chk[COPY_CHUNK_BYTES];
        uint8_t dst_chk[COPY_CHUNK_BYTES];

        err = flash_area_read(src_fa, off, src_chk, chunk);
        if (err) {
            LOG_ERR("Verify read src failed off=0x%zx err=%d", off, err);
            goto out_close;
        }
        err = flash_area_read(dst_fa, off, dst_chk, chunk);
        if (err) {
            LOG_ERR("Verify read dst failed off=0x%zx err=%d", off, err);
            goto out_close;
        }
        if (memcmp(src_chk, dst_chk, chunk) != 0) {
            LOG_ERR("Verify mismatch at off=0x%zx", off);
            err = -EIO;
            goto out_close;
        }
    }

    /* If your system requires recalculating a CRC after any change, do it. */
    err = update_crc();
    if (err) {
        LOG_WRN("update_crc() returned %d", err);
        /* not fatal for the copy itself */
        err = 0;
    }

    LOG_INF("Copied slot %d -> slot %d (8KB)", src_slot, dst_slot);

out_close:
    flash_area_close(dst_fa);
    flash_area_close(src_fa);
    return err;
}

/* ===== Shell glue ===== */

static int cmd_backup_copyinto(const struct shell *sh, size_t argc, char **argv)
{
    ARG_UNUSED(sh);

    if (argc != 3) {
        shell_error(sh, "Usage: backup copyinto <src:0|1> <dst:0|1>");
        return -EINVAL;
    }

    char *endp = NULL;
    long src = strtol(argv[1], &endp, 10);
    if (*argv[1] == '\0' || *endp != '\0') {
        shell_error(sh, "Invalid src '%s'", argv[1]);
        return -EINVAL;
    }
    endp = NULL;
    long dst = strtol(argv[2], &endp, 10);
    if (*argv[2] == '\0' || *endp != '\0') {
        shell_error(sh, "Invalid dst '%s'", argv[2]);
        return -EINVAL;
    }

    int err = copy_slot((int)src, (int)dst);
    if (err) {
        shell_error(sh, "Copy failed: %d", err);
        return err;
    }

    shell_print(sh, "OK: slot %ld -> slot %ld", src, dst);
    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_backup,
    SHELL_CMD_ARG(copyinto, NULL,
                  "copyinto <src:0|1> <dst:0|1>\n"
                  "Copy 8KB from encrypted blob slot <src> into <dst>.",
                  cmd_backup_copyinto, 3, 0),
    SHELL_SUBCMD_SET_END /* Array terminator */
);

SHELL_CMD_REGISTER(backup, &sub_backup, "Encrypted blob backup utilities", NULL);
