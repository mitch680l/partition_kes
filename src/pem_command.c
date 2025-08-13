#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/random/random.h>
#include <nrf_modem_at.h>
#include <dk_buttons_and_leds.h>
#include <modem/modem_key_mgmt.h>
#include "shell_commands.h"
#include "config.h"
#include "fota.h"
#include <zephyr/shell/shell.h>

#define MAX_BLOB 8192

/* Consistent, exact prototypes used by SHELL_CMD_ARG */
static int cmd_keymgmt_put(const struct shell *sh, size_t argc, char **argv);
static int cmd_keymgmt_status(const struct shell *sh, size_t argc, char **argv);
static int cmd_keymgmt_abort(const struct shell *sh, size_t argc, char **argv);
static int cmd_keymgmt_print(const struct shell *sh, size_t argc, char **argv);
static int cmd_keymgmt_delete(const struct shell *sh, size_t argc, char **argv);
/* ... helpers, globals, etc ... */

/* Subcommand table (file scope, not inside any function) */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_keymgmt,
    SHELL_CMD_ARG(put,    NULL,
        "keymgmt put <sec_tag> <ca|cert|key> <one_line>",
        cmd_keymgmt_put,    4, 0),
    SHELL_CMD_ARG(status, NULL,
        "Show current buffering status",
        cmd_keymgmt_status, 1, 0),
    SHELL_CMD_ARG(abort,  NULL,
        "Abort and clear current buffer",
        cmd_keymgmt_abort,  1, 0),
    SHELL_CMD_ARG(print,  NULL,
        "Print current buffer contents with proper line breaks",
        cmd_keymgmt_print,  1, 0),
    SHELL_CMD_ARG(delete, NULL,
        "Delete credential: keymgmt delete <sec_tag> <ca|cert|key>",
        cmd_keymgmt_delete, 3, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(keymgmt, &sub_keymgmt, "Modem key mgmt over PEM lines", NULL);

K_MUTEX_DEFINE(g_lock);

static sec_tag_t g_tag = -1;
static enum modem_key_mgmt_cred_type g_type;
static size_t g_len;
static uint8_t g_buf[MAX_BLOB];  // Static buffer instead of pointer
static bool g_active = false;    // Track if session is active

static const char *type_to_str(enum modem_key_mgmt_cred_type t)
{
	switch (t) {
	case MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN:    return "ca";
	case MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT: return "cert";
	case MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT: return "key";
	default: return "?";
	}
}

static bool map_type(const char *s, enum modem_key_mgmt_cred_type *out)
{
	if (!strcmp(s, "ca") || !strcmp(s, "cacert") || !strcmp(s, "cachain")) {
		*out = MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN; return true;
	}
	if (!strcmp(s, "cert") || !strcmp(s, "client") || !strcmp(s, "clientcert")) {
		*out = MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT; return true;
	}
	if (!strcmp(s, "key") || !strcmp(s, "privkey") || !strcmp(s, "private")) {
		*out = MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT; return true;
	}
	return false;
}

static const char *end_marker_for_type(enum modem_key_mgmt_cred_type t)
{
	if (t == MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN ||
	    t == MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT) {
		return "-----END CERTIFICATE-----";
	}
	/* keys handled by list below */
	return NULL;
}

static bool line_is_key_end(const char *line_trim)
{
	static const char *markers[] = {
		"-----END PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----",
		"-----END EC PRIVATE KEY-----",
	};
	for (size_t i = 0; i < sizeof(markers)/sizeof(markers[0]); i++) {
		if (strcmp(line_trim, markers[i]) == 0) return true;
	}
	return false;
}

static void session_reset(void)
{
	g_len = 0; 
	g_tag = -1;
	g_active = false;
}

static int session_ensure(sec_tag_t tag, enum modem_key_mgmt_cred_type type)
{
	if (!g_active) {
		g_len = 0; 
		g_tag = tag; 
		g_type = type;
		g_active = true;
		return 0;
	}
	if (g_tag == tag && g_type == type) return 0;
	return -EBUSY;
}

static char *trim_eol(char *s)
{
	size_t n = strlen(s);
	while (n && (s[n-1] == '\n' || s[n-1] == '\r')) { s[--n] = '\0'; }
	return s;
}

/* keymgmt put <sec_tag> <ca|cert|key> <one_line> */
static int cmd_keymgmt_put(const struct shell *sh, size_t argc, char **argv)
{
	AUTH_TOUCH();
	REQUIRE_AUTH(sh);

	if (argc < 4) {
		shell_error(sh, "Usage: keymgmt put <sec_tag> <ca|cert|key> <one_line>");
		return -EINVAL;
	}

	int ret = 0;
	sec_tag_t tag = (sec_tag_t)strtol(argv[1], NULL, 10);
	enum modem_key_mgmt_cred_type type;
	if (!map_type(argv[2], &type)) {
		shell_error(sh, "Unknown type: %s (use: ca|cert|key)", argv[2]);
		return -EINVAL;
	}

	char *line = argv[3];
	size_t linelen = strlen(line);

	k_mutex_lock(&g_lock, K_FOREVER);
	do {
		ret = session_ensure(tag, type);
		if (ret == -EBUSY) {
			shell_error(sh, "Busy: in-progress tag=%d type=%s; finish or 'keymgmt abort'",
			            g_tag, type_to_str(g_type));
			break;
		} else if (ret) {
			shell_error(sh, "OOM");
			break;
		}

		if (g_len + linelen + 1 > MAX_BLOB) {
			shell_error(sh, "Too big (> %u)", MAX_BLOB);
			ret = -EOVERFLOW;
			break;
		}

		memcpy(g_buf + g_len, line, linelen);
		g_len += linelen;
		g_buf[g_len++] = '\n';

		/* Detect END line exactly (GUI sends one PEM line per call) */
		bool done = false;
		if (linelen < 128) {
			char tmp[128];
			memcpy(tmp, line, linelen);
			tmp[linelen] = '\0';
			char *t = trim_eol(tmp);

			const char *cert_end = end_marker_for_type(type);
			if (cert_end) {
				done = (strcmp(t, cert_end) == 0);
			} else {
				done = line_is_key_end(t);
			}
		}

		if (done) {
			int w = modem_key_mgmt_write(g_tag, g_type, g_buf, g_len);
			if (w) {
				shell_error(sh, "modem_key_mgmt_write err %d", w);
				ret = w;
			} else {
				shell_print(sh, "OK wrote tag=%d type=%s (%u bytes)",
				            g_tag, type_to_str(g_type), (unsigned)g_len);
			}
			session_reset();
		} else {
			shell_print(sh, "APPEND %u (tag=%d type=%s size=%u)",
			            (unsigned)linelen, g_tag, type_to_str(g_type), (unsigned)g_len);
		}
	} while (0);
	k_mutex_unlock(&g_lock);
	return ret;
}

/* keymgmt status */
static int cmd_keymgmt_status(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc); ARG_UNUSED(argv);
	AUTH_TOUCH();
	REQUIRE_AUTH(sh);
	k_mutex_lock(&g_lock, K_FOREVER);
	if (!g_active) {
		shell_print(sh, "IDLE");
	} else {
		shell_print(sh, "IN-PROGRESS tag=%d type=%s size=%u/%u",
		            g_tag, type_to_str(g_type), (unsigned)g_len, (unsigned)MAX_BLOB);
	}
	k_mutex_unlock(&g_lock);
	return 0;
}

/* keymgmt abort */
static int cmd_keymgmt_abort(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc); ARG_UNUSED(argv);
	AUTH_TOUCH();
	REQUIRE_AUTH(sh);
	k_mutex_lock(&g_lock, K_FOREVER);
	if (!g_active) {
		shell_print(sh, "No active session");
	} else {
		session_reset();
		shell_print(sh, "Aborted");
	}
	k_mutex_unlock(&g_lock);
	return 0;
}

/* keymgmt print */
static int cmd_keymgmt_print(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc); ARG_UNUSED(argv);
	AUTH_TOUCH();
	REQUIRE_AUTH(sh);
	
	k_mutex_lock(&g_lock, K_FOREVER);
	if (!g_active) {
		shell_print(sh, "No active session to print");
		k_mutex_unlock(&g_lock);
		return 0;
	}
	
	shell_print(sh, "=== Current buffer (tag=%d type=%s, %u bytes) ===", 
	            g_tag, type_to_str(g_type), (unsigned)g_len);
	
	/* Safety check */
	if (g_len == 0) {
		shell_print(sh, "(empty buffer)");
		shell_print(sh, "=== End of buffer ===");
		k_mutex_unlock(&g_lock);
		return 0;
	}
	
	/* Print buffer contents line by line with safer approach */
	char line_buf[128]; /* Safe line buffer - most PEM lines are <80 chars */
	size_t start = 0;
	size_t line_count = 0;
	
	for (size_t i = 0; i < g_len; i++) {
		if (g_buf[i] == '\n' || i == g_len - 1) {
			/* Found end of line or end of buffer */
			size_t line_len = (g_buf[i] == '\n') ? (i - start) : (i - start + 1);
			
			if (line_len > 0) {
				/* Clamp line length to prevent buffer overflow */
				size_t safe_len = (line_len < sizeof(line_buf) - 1) ? line_len : (sizeof(line_buf) - 1);
				
				/* Copy line to safe buffer and null-terminate */
				memcpy(line_buf, &g_buf[start], safe_len);
				line_buf[safe_len] = '\0';
				
				/* Use shell_print instead of printk for safer output */
				shell_print(sh, "%s", line_buf);
				
				/* Add safety break for very large buffers */
				line_count++;
				if (line_count % 10 == 0) {
					k_msleep(50); /* Longer delay every 10 lines */
				} else {
					k_msleep(5);  /* Short delay between lines */
				}
				
				/* Safety limit to prevent terminal overflow */
				if (line_count > 200) {
					shell_print(sh, "... (output truncated after 200 lines)");
					break;
				}
			}
			start = i + 1;
		}
	}
	
	shell_print(sh, "=== End of buffer (%u lines printed) ===", (unsigned)line_count);
	k_mutex_unlock(&g_lock);
	return 0;
}

/* keymgmt delete <sec_tag> <ca|cert|key> */
static int cmd_keymgmt_delete(const struct shell *sh, size_t argc, char **argv)
{
	AUTH_TOUCH();
	REQUIRE_AUTH(sh);

	if (argc < 3) {
		shell_error(sh, "Usage: keymgmt delete <sec_tag> <ca|cert|key>");
		return -EINVAL;
	}

	sec_tag_t tag = (sec_tag_t)strtol(argv[1], NULL, 10);
	enum modem_key_mgmt_cred_type type;
	
	if (!map_type(argv[2], &type)) {
		shell_error(sh, "Unknown type: %s (use: ca|cert|key)", argv[2]);
		return -EINVAL;
	}

	/* Check if we're trying to delete something that's currently being buffered */
	k_mutex_lock(&g_lock, K_FOREVER);
	if (g_active && g_tag == tag && g_type == type) {
		shell_warn(sh, "Warning: Clearing active buffer for tag=%d type=%s", 
		           g_tag, type_to_str(g_type));
		session_reset();
	}
	k_mutex_unlock(&g_lock);

	/* Attempt to delete the credential */
	int ret = modem_key_mgmt_delete(tag, type);
	if (ret == 0) {
		shell_print(sh, "OK deleted tag=%d type=%s", tag, type_to_str(type));
	} else if (ret == -ENOENT) {
		shell_warn(sh, "Credential not found: tag=%d type=%s", tag, type_to_str(type));
	} else {
		shell_error(sh, "Failed to delete tag=%d type=%s (err %d)", 
		            tag, type_to_str(type), ret);
	}

	return ret;
}