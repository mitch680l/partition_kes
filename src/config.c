#include "config.h"
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
#include <dk_buttons_and_leds.h>
#include <modem/modem_key_mgmt.h>
char mqtt_client_id[MQTT_MAX_STR_LEN] = "nrid4148";               
char firmware_filename[MQTT_MAX_STR_LEN] = "blinky_2.signed.bin";
int  mqtt_broker_port = 8883;
int interval_mqtt = 100;
int fota_interval_ms = 10 * 60 * 1000;
int gps_target_rate = 25;
char json_payload[512] = "NO PVT";
static char user_buf[64];
static char pass_buf[64];
LOG_MODULE_REGISTER(configuration, LOG_LEVEL_INF);
const char *mqtt_broker_host = "NULL";
const char *fota_host = "NULL"; 
struct mqtt_utf8 struct_pass;
struct mqtt_utf8 struct_user;


void set_user_pass(void)
{
    LOG_INF("SETT USER PASS");
    const char *password = "NULL";
    const char *username = "NULL";
    //password = get_config("password");
    if (!password || strcmp(password, "NULL") == 0) {
        password = "Kalscott123";
    }
    strncpy(pass_buf, password, sizeof(pass_buf) - 1);
    pass_buf[sizeof(pass_buf) - 1] = '\0';

    //username = get_config("username");
    if (!username || strcmp(username, "NULL") == 0) {
        username = "admin";
    }
    strncpy(user_buf, username, sizeof(user_buf) - 1);
    user_buf[sizeof(user_buf) - 1] = '\0';

    LOG_INF("Setting MQTT username: %s", user_buf);
    LOG_INF("Setting MQTT password: %s", pass_buf);

    struct_pass.utf8 = (uint8_t *)pass_buf;
    struct_pass.size = strlen(pass_buf);
    struct_user.utf8 = (uint8_t *)user_buf;
    struct_user.size = strlen(user_buf);
}

void clear_user_pass(void)
{
    struct_pass.utf8 = NULL;
    struct_pass.size = 0;
    struct_user.utf8 = NULL;
    struct_user.size = 0;
    LOG_INF("Cleared MQTT username and password");
}

void config_init() {
    


    //mqtt_broker_host = get_config("mqtt_broker_host");
    if (!mqtt_broker_host || strcmp(mqtt_broker_host, "NULL") == 0) {
    mqtt_broker_host = "18.234.99.151";  // fallback default
    }

    //fota_host = get_config("fota_host");
    if (!fota_host || strcmp(fota_host, "NULL") == 0) {
        LOG_WRN("mqtt_broker_host not found, using default.");
        fota_host = "18.234.99.151";
    }
}