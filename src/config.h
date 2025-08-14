#include <stdbool.h>
#include <stdint.h>
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
#define GPS_READ_BUFFER_SIZE 126  
#define GPS_STARTUP_DELAY_MS 2000  
#define GPS_CONFIG_TIMEOUT_MS 500  
#define GPS_MAX_CONFIG_ATTEMPTS 3
#define M10S_ADDR 0x42
#define NAV_PVT_LEN 92

#define MQTT_MAX_STR_LEN 128
#define MQTT_THREAD_STACK_SIZE 2048
#define MQTT_THREAD_PRIORITY 1
#define JSON_BUF_SIZE 516
#define BAD_PUBLISH_LIMIT 5
#define MQTT_RECONNECT_DELAY_SEC 10


#define MAX_INPUT_LEN 256
#define BLOB_HEADER_SIZE 0
#define ENTRY_SIZE 128

#define MAX_ENTRIES         63
#define MAX_IV_LEN          16
#define MAX_AAD_LEN         64
#define MAX_CIPHERTEXT_LEN  256
#define FLASH_PAGE_SIZE  4096 
#define ENTRIES_PER_PAGE (FLASH_PAGE_SIZE / ENTRY_SIZE)
#define CONFIG_PAGE_COUNT 2  
#define TOTAL_ENTRIES     (CONFIG_PAGE_COUNT * ENTRIES_PER_PAGE) 
#define ENCRYPTED_BLOB_ADDR ((const uint8_t *)0xfb000)
#define ENCRYPTED_BLOB_ADDR_2 ((const uint8_t *)0xfe000)
#define ENCRYPTED_BLOB_SIZE 8192 
#define FLASH_CRC_PAGE_OFFSET (CONFIG_PAGE_COUNT * FLASH_PAGE_SIZE)
#define FLASH_PAGE_CRC_SIZE  (ENCRYPTED_BLOB_SIZE - FLASH_CRC_PAGE_OFFSET)
#define CRC_LOCATION_OFFSET (ENCRYPTED_BLOB_SIZE - 4)


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

#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE (100)
#define NRF_CRYPTO_EXAMPLE_AES_BLOCK_SIZE (16)
#define NRF_CRYPTO_EXAMPLE_AES_IV_SIZE (12)
#define NRF_CRYPTO_EXAMPLE_AES_ADDITIONAL_SIZE (35)
#define NRF_CRYPTO_EXAMPLE_AES_GCM_TAG_LENGTH (16)
#define AES_KEY_SIZE (32) 
#define DECRYPTED_OUTPUT_MAX 256



#define MAX_TRIES        3
#define LOCKOUT_MS       30000     
#define AUTO_LOGOUT_MS   60000      

#define MAX_BLOB (8 * 1024) 
#define PBKDF2_ITERATIONS 64000u
extern char firmware_filename[MQTT_MAX_STR_LEN];
extern char json_payload[512];
extern char sensor_payload[512];
extern char topic_gps[64];
extern char topic_sensor[64];
extern char topic_lte[64];


extern struct mqtt_utf8 struct_pass;
extern struct mqtt_utf8 struct_user;



typedef struct {
    bool lte_en;
    bool irid_en;
    bool psm_en;
    bool hw_en;
    bool mdm_en;
    bool gnss_en;
    bool imu_en;
    bool comp_en;
    bool baro_en;
    bool mqtt_en;
    bool ota_en;
    bool debug_mode;
    bool factory_mode;

} system_enable_t;

extern system_enable_t sys_enable_config;
#define SYS_EN_LTE_EN        (1 << 0)
#define SYS_EN_IRID_EN       (1 << 1)
#define SYS_EN_PSM_EN        (1 << 2)
#define SYS_EN_HW_EN         (1 << 3)
#define SYS_EN_MDM_EN        (1 << 4)
#define SYS_EN_GNSS_EN       (1 << 5)
#define SYS_EN_IMU_EN        (1 << 6)
#define SYS_EN_COMP_EN       (1 << 7)
#define SYS_EN_BARO_EN       (1 << 8)
#define SYS_EN_MQTT_EN       (1 << 9)
#define SYS_EN_OTA_EN        (1 << 10)
#define SYS_EN_DEBUG_MODE    (1 << 11)
#define SYS_EN_FACTORY_MODE  (1 << 12)

typedef struct {
    int publish_rate;
    char broker_addr[64];
    int broker_port;
    char client_id[64];
    char username[64];
    char password[64];
    bool tls_enabled;
    int qos;
} mqtt_config_t;


typedef struct {
    int check_interval;
    char server_addr[64];
    int server_port;
    char username[64];
    char password[64];
    bool tls_enabled;
    char cert_tag[64];
} ota_config_t;


typedef struct {
    char sn[32];
    char hw_ver[16];    
    char fw_ver[16];   
    bool power_enabled; 
} hardware_info_t;

typedef struct {
    char make[32];   
    char model[32]; 
    char fw_ver[16];    
    char imei[20];    
    char sim[32];    
    char esim[32];      
    uint16_t lte_bandmask;
} modem_info_t;

typedef struct {
    int  sampling_rate;     
    int  filter_window;     
    bool auto_calibrate;  
} sensor_config_t;

typedef struct {
    int update_rate;
    char version[32];
    uint8_t constellation_mask;
    int accuracy_threshold;
} gnss_config_t;

typedef struct {
    char uas_num[32];
    char description[64];
    char uas_status[64];
    char field2[64];
    char field3[64];
    char field4[64];
} customer_info_t;

typedef struct {
    char msg_format[16];  
    char gps_format[16];   
    char units[16];       
} message_settings_t;

typedef struct {
    uint8_t iv[MAX_IV_LEN];
    uint8_t iv_len;

    uint8_t aad[MAX_AAD_LEN];
    uint16_t aad_len;

    uint8_t ciphertext[MAX_CIPHERTEXT_LEN];
    uint16_t ciphertext_len;

    uint32_t mem_offset;  
} ConfigEntry;


extern ConfigEntry entries[MAX_ENTRIES];
extern int num_entries;

extern mqtt_config_t *mqtt_config;
extern ota_config_t *ota_config;
extern hardware_info_t *hw_info;
extern modem_info_t *modem_info;
extern sensor_config_t *sensor_config;
extern gnss_config_t *gnss_config;
extern customer_info_t *customer_info;
extern message_settings_t *message_settings;

void parse_encrypted_blob(void);
const char *get_config(const char *aad);
void config_init(void);
uint32_t manual_crc32(const uint8_t *data, size_t len);
int update_crc(void);
