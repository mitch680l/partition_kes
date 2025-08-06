#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/device.h>
#include <zephyr/drivers/i2c.h>
#include <stdlib.h>
#include "../drivers/led/led_driver.h"  // Include your header file

// Global device instance - you may need to modify this based on your setup
static struct ktd2026_device ktd_dev;
static bool device_initialized = false;

// Helper function to ensure device is initialized
static int ensure_device_init(const struct shell *sh)
{
    if (!device_initialized) {
        // You may need to modify this based on your I2C device tree setup
        const struct device *i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
        
        if (!device_is_ready(i2c_dev)) {
            shell_error(sh, "I2C device not ready");
            return -ENODEV;
        }
        
        int ret = ktd2026_init(&ktd_dev, i2c_dev, KTD2026_I2C_ADDR);
        if (ret) {
            shell_error(sh, "Failed to initialize KTD2026: %d", ret);
            return ret;
        }
        
        device_initialized = true;
        shell_print(sh, "KTD2026 device initialized");
    }
    return 0;
}

// ============================================================================
// BASIC REGISTER COMMANDS
// ============================================================================

// Shell command: ktd2026 init
static int cmd_ktd2026_init(const struct shell *sh, size_t argc, char **argv)
{
    const struct device *i2c_dev;
    uint16_t addr = KTD2026_I2C_ADDR;
    
    if (argc > 1) {
        // Optional I2C device name
        i2c_dev = device_get_binding(argv[1]);
        if (!i2c_dev) {
            shell_error(sh, "I2C device '%s' not found", argv[1]);
            return -ENODEV;
        }
    } else {
        // Default to i2c0 - modify as needed
        i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
    }
    
    if (argc > 2) {
        // Optional I2C address
        addr = strtoul(argv[2], NULL, 16);
    }
    
    if (!device_is_ready(i2c_dev)) {
        shell_error(sh, "I2C device not ready");
        return -ENODEV;
    }
    
    int ret = ktd2026_init(&ktd_dev, i2c_dev, addr);
    if (ret) {
        shell_error(sh, "Failed to initialize KTD2026: %d", ret);
        return ret;
    }
    
    device_initialized = true;
    shell_print(sh, "KTD2026 initialized at address 0x%02X", addr);
    return 0;
}

// Shell command: ktd2026 en_rst <value>
static int cmd_ktd2026_en_rst(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 en_rst <value>");
        return -EINVAL;
    }
    
    uint8_t val = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_write_en_rst(&ktd_dev, val);
    
    if (ret) {
        shell_error(sh, "Failed to write EN_RST register: %d", ret);
        return ret;
    }
    
    shell_print(sh, "EN_RST register set to 0x%02X", val);
    return 0;
}

// Shell command: ktd2026 flash_period <value>
static int cmd_ktd2026_flash_period(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 flash_period <value>");
        return -EINVAL;
    }
    
    uint8_t val = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_write_flash_period(&ktd_dev, val);
    
    if (ret) {
        shell_error(sh, "Failed to write FLASH_PERIOD register: %d", ret);
        return ret;
    }
    
    shell_print(sh, "FLASH_PERIOD register set to 0x%02X", val);
    return 0;
}

// Shell command: ktd2026 flash_on1 <value>
static int cmd_ktd2026_flash_on1(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 flash_on1 <value>");
        return -EINVAL;
    }
    
    uint8_t val = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_write_flash_on1(&ktd_dev, val);
    
    if (ret) {
        shell_error(sh, "Failed to write FLASH_ON1 register: %d", ret);
        return ret;
    }
    
    shell_print(sh, "FLASH_ON1 register set to 0x%02X", val);
    return 0;
}

// Shell command: ktd2026 flash_on2 <value>
static int cmd_ktd2026_flash_on2(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 flash_on2 <value>");
        return -EINVAL;
    }
    
    uint8_t val = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_write_flash_on2(&ktd_dev, val);
    
    if (ret) {
        shell_error(sh, "Failed to write FLASH_ON2 register: %d", ret);
        return ret;
    }
    
    shell_print(sh, "FLASH_ON2 register set to 0x%02X", val);
    return 0;
}

// Shell command: ktd2026 channel_ctrl <value>
static int cmd_ktd2026_channel_ctrl(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 channel_ctrl <value>");
        return -EINVAL;
    }
    
    uint8_t val = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_write_channel_ctrl(&ktd_dev, val);
    
    if (ret) {
        shell_error(sh, "Failed to write CHANNEL_CTRL register: %d", ret);
        return ret;
    }
    
    shell_print(sh, "CHANNEL_CTRL register set to 0x%02X", val);
    return 0;
}

// Shell command: ktd2026 ramp_rate <value>
static int cmd_ktd2026_ramp_rate(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 ramp_rate <value>");
        return -EINVAL;
    }
    
    uint8_t val = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_write_ramp_rate(&ktd_dev, val);
    
    if (ret) {
        shell_error(sh, "Failed to write RAMP_RATE register: %d", ret);
        return ret;
    }
    
    shell_print(sh, "RAMP_RATE register set to 0x%02X", val);
    return 0;
}

// Shell command: ktd2026 led1_iout <value>
static int cmd_ktd2026_led1_iout(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 led1_iout <value>");
        return -EINVAL;
    }
    
    uint8_t val = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_write_led1_iout(&ktd_dev, val);
    
    if (ret) {
        shell_error(sh, "Failed to write LED1_IOUT register: %d", ret);
        return ret;
    }
    
    shell_print(sh, "LED1_IOUT register set to 0x%02X", val);
    return 0;
}

// Shell command: ktd2026 led2_iout <value>
static int cmd_ktd2026_led2_iout(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 led2_iout <value>");
        return -EINVAL;
    }
    
    uint8_t val = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_write_led2_iout(&ktd_dev, val);
    
    if (ret) {
        shell_error(sh, "Failed to write LED2_IOUT register: %d", ret);
        return ret;
    }
    
    shell_print(sh, "LED2_IOUT register set to 0x%02X", val);
    return 0;
}

// Shell command: ktd2026 led3_iout <value>
static int cmd_ktd2026_led3_iout(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 led3_iout <value>");
        return -EINVAL;
    }
    
    uint8_t val = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_write_led3_iout(&ktd_dev, val);
    
    if (ret) {
        shell_error(sh, "Failed to write LED3_IOUT register: %d", ret);
        return ret;
    }
    
    shell_print(sh, "LED3_IOUT register set to 0x%02X", val);
    return 0;
}

// ============================================================================
// REG0 MODE HELPER COMMANDS
// ============================================================================

// Shell command: ktd2026 set_reset_mode <mode>
static int cmd_ktd2026_set_reset_mode(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 set_reset_mode <mode>");
        shell_print(sh, "Modes: 0=normal, 1=timer1, 2=timer2, 3=timer3, 4=timer4, 5=reg_reset, 6=digital_reset, 7=chip_reset");
        return -EINVAL;
    }
    
    enum ktd2026_reset_mode mode = strtoul(argv[1], NULL, 0);
    int ret = ktd2026_set_reset_mode(&ktd_dev, mode);
    
    if (ret) {
        shell_error(sh, "Failed to set reset mode: %d", ret);
        return ret;
    }
    
    shell_print(sh, "Reset mode set to %d", mode);
    return 0;
}

// Timer slot selection commands
static int cmd_ktd2026_select_timer_slot1(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_select_timer_slot1(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to select timer slot 1: %d", ret);
        return ret;
    }
    shell_print(sh, "Timer slot 1 selected");
    return 0;
}

static int cmd_ktd2026_select_timer_slot2(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_select_timer_slot2(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to select timer slot 2: %d", ret);
        return ret;
    }
    shell_print(sh, "Timer slot 2 selected");
    return 0;
}

static int cmd_ktd2026_select_timer_slot3(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_select_timer_slot3(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to select timer slot 3: %d", ret);
        return ret;
    }
    shell_print(sh, "Timer slot 3 selected");
    return 0;
}

static int cmd_ktd2026_select_timer_slot4(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_select_timer_slot4(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to select timer slot 4: %d", ret);
        return ret;
    }
    shell_print(sh, "Timer slot 4 selected");
    return 0;
}

// Reset commands
static int cmd_ktd2026_reset_registers_only(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_reset_registers_only(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to reset registers: %d", ret);
        return ret;
    }
    shell_print(sh, "Registers reset");
    return 0;
}

static int cmd_ktd2026_reset_digital_only(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_reset_digital_only(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to reset digital: %d", ret);
        return ret;
    }
    shell_print(sh, "Digital reset performed");
    return 0;
}

static int cmd_ktd2026_reset_chip(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_reset_chip(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to reset chip: %d", ret);
        return ret;
    }
    shell_print(sh, "Chip reset performed");
    device_initialized = false; // Need to reinitialize after chip reset
    return 0;
}

// Enable control commands
static int cmd_ktd2026_set_enable_control_scl_sda_high(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_set_enable_control_scl_sda_high(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to set enable control: %d", ret);
        return ret;
    }
    shell_print(sh, "Enable control set to SCL/SDA high");
    return 0;
}

static int cmd_ktd2026_set_enable_control_scl_sda_toggle(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_set_enable_control_scl_sda_toggle(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to set enable control: %d", ret);
        return ret;
    }
    shell_print(sh, "Enable control set to SCL/SDA toggle");
    return 0;
}

static int cmd_ktd2026_set_enable_control_scl_high(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_set_enable_control_scl_high(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to set enable control: %d", ret);
        return ret;
    }
    shell_print(sh, "Enable control set to SCL high");
    return 0;
}

static int cmd_ktd2026_set_enable_control_always_on(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_set_enable_control_always_on(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to set enable control: %d", ret);
        return ret;
    }
    shell_print(sh, "Enable control set to always on");
    return 0;
}

// Rise/fall scaling commands
static int cmd_ktd2026_set_rise_fall_scale_1x(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_set_rise_fall_scale_1x(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to set rise/fall scale: %d", ret);
        return ret;
    }
    shell_print(sh, "Rise/fall scale set to 1x");
    return 0;
}

static int cmd_ktd2026_set_rise_fall_scale_2x_slower(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_set_rise_fall_scale_2x_slower(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to set rise/fall scale: %d", ret);
        return ret;
    }
    shell_print(sh, "Rise/fall scale set to 2x slower");
    return 0;
}

static int cmd_ktd2026_set_rise_fall_scale_4x_slower(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_set_rise_fall_scale_4x_slower(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to set rise/fall scale: %d", ret);
        return ret;
    }
    shell_print(sh, "Rise/fall scale set to 4x slower");
    return 0;
}

static int cmd_ktd2026_set_rise_fall_scale_8x_faster(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    int ret = ktd2026_set_rise_fall_scale_8x_faster(&ktd_dev);
    if (ret) {
        shell_error(sh, "Failed to set rise/fall scale: %d", ret);
        return ret;
    }
    shell_print(sh, "Rise/fall scale set to 8x faster");
    return 0;
}

// ============================================================================
// FLASH TIMING COMMANDS
// ============================================================================

// Shell command: ktd2026 set_flash_period <period_sec> <ramp_mode>
static int cmd_ktd2026_set_flash_period(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 3) {
        shell_error(sh, "Usage: ktd2026 set_flash_period <period_sec> <ramp_mode>");
        shell_print(sh, "Ramp modes: 0=normal, 1=ramp_up, 2=ramp_down, 3=ramp_both");
        return -EINVAL;
    }
    
    float period_sec = strtof(argv[1], NULL);
    enum ktd2026_ramp_mode ramp_mode = strtoul(argv[2], NULL, 0);
    
    int ret = ktd2026_set_flash_period(&ktd_dev, period_sec, ramp_mode);
    
    if (ret) {
        shell_error(sh, "Failed to set flash period: %d", ret);
        return ret;
    }
    
    shell_print(sh, "Flash period set to %.3f sec, ramp mode %d", period_sec, ramp_mode);
    return 0;
}

// Shell command: ktd2026 set_flash_on1 <percent>
static int cmd_ktd2026_set_flash_on1(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 set_flash_on1 <percent>");
        return -EINVAL;
    }
    
    float percent = strtof(argv[1], NULL);
    int ret = ktd2026_set_flash_on1(&ktd_dev, percent);
    
    if (ret) {
        shell_error(sh, "Failed to set flash on1: %d", ret);
        return ret;
    }
    
    shell_print(sh, "Flash ON1 set to %.1f%%", percent);
    return 0;
}

// Shell command: ktd2026 set_flash_on2 <percent>
static int cmd_ktd2026_set_flash_on2(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 2) {
        shell_error(sh, "Usage: ktd2026 set_flash_on2 <percent>");
        return -EINVAL;
    }
    
    float percent = strtof(argv[1], NULL);
    int ret = ktd2026_set_flash_on2(&ktd_dev, percent);
    
    if (ret) {
        shell_error(sh, "Failed to set flash on2: %d", ret);
        return ret;
    }
    
    shell_print(sh, "Flash ON2 set to %.1f%%", percent);
    return 0;
}

// ============================================================================
// LED MODE CONTROL COMMANDS
// ============================================================================

// Shell command: ktd2026 set_led_mode <led_index> <mode>
static int cmd_ktd2026_set_led_mode(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 3) {
        shell_error(sh, "Usage: ktd2026 set_led_mode <led_index> <mode>");
        shell_print(sh, "LED index: 1, 2, or 3");
        shell_print(sh, "Modes: 0=off, 1=on, 2=pwm1, 3=pwm2");
        return -EINVAL;
    }
    
    uint8_t led_index = strtoul(argv[1], NULL, 0);
    enum ktd2026_led_mode mode = strtoul(argv[2], NULL, 0);
    
    int ret = ktd2026_set_led_mode(&ktd_dev, led_index, mode);
    
    if (ret) {
        shell_error(sh, "Failed to set LED mode: %d", ret);
        return ret;
    }
    
    shell_print(sh, "LED%d mode set to %d", led_index, mode);
    return 0;
}

// ============================================================================
// RAMP TIMES COMMANDS
// ============================================================================

// Shell command: ktd2026 set_ramp_times <rise_index> <fall_index>
static int cmd_ktd2026_set_ramp_times(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 3) {
        shell_error(sh, "Usage: ktd2026 set_ramp_times <rise_index> <fall_index>");
        shell_print(sh, "Index range: 0-15 (see datasheet for timing values)");
        return -EINVAL;
    }
    
    uint8_t rise_index = strtoul(argv[1], NULL, 0);
    uint8_t fall_index = strtoul(argv[2], NULL, 0);
    
    int ret = ktd2026_set_ramp_times(&ktd_dev, rise_index, fall_index);
    
    if (ret) {
        shell_error(sh, "Failed to set ramp times: %d", ret);
        return ret;
    }
    
    shell_print(sh, "Ramp times set: rise_index=%d, fall_index=%d", rise_index, fall_index);
    return 0;
}

// ============================================================================
// LED CURRENT COMMANDS
// ============================================================================

// Shell command: ktd2026 set_led_current <led_index> <current_ma>
static int cmd_ktd2026_set_led_current(const struct shell *sh, size_t argc, char **argv)
{
    if (ensure_device_init(sh)) return -1;
    
    if (argc != 3) {
        shell_error(sh, "Usage: ktd2026 set_led_current <led_index> <current_ma>");
        shell_print(sh, "LED index: 1, 2, or 3");
        shell_print(sh, "Current: 0.0 to 24.0 mA (typical range)");
        return -EINVAL;
    }
    
    uint8_t led_index = strtoul(argv[1], NULL, 0);
    float current_ma = strtof(argv[2], NULL);
    
    int ret = ktd2026_set_led_current(&ktd_dev, led_index, current_ma);
    
    if (ret) {
        shell_error(sh, "Failed to set LED current: %d", ret);
        return ret;
    }
    
    shell_print(sh, "LED%d current set to %.1f mA", led_index, current_ma);
    return 0;
}

// ============================================================================
// HELP COMMAND
// ============================================================================

// Help command
static int cmd_ktd2026_help(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "KTD2026 LED Driver Commands:");
    shell_print(sh, "");
    shell_print(sh, "BASIC REGISTER COMMANDS:");
    shell_print(sh, "  init [i2c_dev] [addr]    - Initialize device");
    shell_print(sh, "  en_rst <value>           - Write to EN_RST register");
    shell_print(sh, "  flash_period <value>     - Write to FLASH_PERIOD register");
    shell_print(sh, "  flash_on1 <value>        - Write to FLASH_ON1 register");
    shell_print(sh, "  flash_on2 <value>        - Write to FLASH_ON2 register");
    shell_print(sh, "  channel_ctrl <value>     - Write to CHANNEL_CTRL register");
    shell_print(sh, "  ramp_rate <value>        - Write to RAMP_RATE register");
    shell_print(sh, "  led1_iout <value>        - Write to LED1_IOUT register");
    shell_print(sh, "  led2_iout <value>        - Write to LED2_IOUT register");
    shell_print(sh, "  led3_iout <value>        - Write to LED3_IOUT register");
    shell_print(sh, "");
    shell_print(sh, "REG0 MODE HELPERS:");
    shell_print(sh, "  set_reset_mode <mode>    - Set reset mode (0-7)");
    shell_print(sh, "  timer_slot1              - Select timer slot 1");
    shell_print(sh, "  timer_slot2              - Select timer slot 2");
    shell_print(sh, "  timer_slot3              - Select timer slot 3");
    shell_print(sh, "  timer_slot4              - Select timer slot 4");
    shell_print(sh, "  reset_registers          - Reset registers only");
    shell_print(sh, "  reset_digital            - Reset digital only");
    shell_print(sh, "  reset_chip               - Reset entire chip");
    shell_print(sh, "  enable_scl_sda_high      - Enable control: SCL/SDA high");
    shell_print(sh, "  enable_scl_sda_toggle    - Enable control: SCL/SDA toggle");
    shell_print(sh, "  enable_scl_high          - Enable control: SCL high");
    shell_print(sh, "  enable_always_on         - Enable control: always on");
    shell_print(sh, "  scale_1x                 - Rise/fall scale: 1x");
    shell_print(sh, "  scale_2x_slower          - Rise/fall scale: 2x slower");
    shell_print(sh, "  scale_4x_slower          - Rise/fall scale: 4x slower");
    shell_print(sh, "  scale_8x_faster          - Rise/fall scale: 8x faster");
    shell_print(sh, "");
    shell_print(sh, "FLASH TIMING:");
    shell_print(sh, "  set_flash_period <sec> <ramp> - Set flash period and ramp mode");
    shell_print(sh, "  set_flash_on1 <percent>  - Set flash ON1 percentage");
    shell_print(sh, "  set_flash_on2 <percent>  - Set flash ON2 percentage");
    shell_print(sh, "");
    shell_print(sh, "LED CONTROL:");
    shell_print(sh, "  set_led_mode <led> <mode> - Set LED mode (led:1-3, mode:0-3)");
    shell_print(sh, "  set_ramp_times <rise> <fall> - Set ramp rise/fall times (0-15)");
    shell_print(sh, "  set_led_current <led> <ma> - Set LED current in mA");
    shell_print(sh, "");
    shell_print(sh, "Values can be decimal, hex (0x), or octal (0)");
    shell_print(sh, "Example: ktd2026 set_led_current 1 12.5");
    return 0;
}

// ============================================================================
// SUBCOMMAND DEFINITIONS
// ============================================================================

// Basic register subcommands
SHELL_STATIC_SUBCMD_SET_CREATE(sub_ktd2026_basic,
    SHELL_CMD(init, NULL, "Initialize KTD2026 device", cmd_ktd2026_init),
    SHELL_CMD(en_rst, NULL, "Write EN_RST register", cmd_ktd2026_en_rst),
    SHELL_CMD(flash_period, NULL, "Write FLASH_PERIOD register", cmd_ktd2026_flash_period),
    SHELL_CMD(flash_on1, NULL, "Write FLASH_ON1 register", cmd_ktd2026_flash_on1),
    SHELL_CMD(flash_on2, NULL, "Write FLASH_ON2 register", cmd_ktd2026_flash_on2),
    SHELL_CMD(channel_ctrl, NULL, "Write CHANNEL_CTRL register", cmd_ktd2026_channel_ctrl),
    SHELL_CMD(ramp_rate, NULL, "Write RAMP_RATE register", cmd_ktd2026_ramp_rate),
    SHELL_CMD(led1_iout, NULL, "Write LED1_IOUT register", cmd_ktd2026_led1_iout),
    SHELL_CMD(led2_iout, NULL, "Write LED2_IOUT register", cmd_ktd2026_led2_iout),
    SHELL_CMD(led3_iout, NULL, "Write LED3_IOUT register", cmd_ktd2026_led3_iout),
    SHELL_SUBCMD_SET_END
);

// REG0 mode helper subcommands
SHELL_STATIC_SUBCMD_SET_CREATE(sub_ktd2026_mode,
    SHELL_CMD(set_reset_mode, NULL, "Set reset mode", cmd_ktd2026_set_reset_mode),
    SHELL_CMD(timer_slot1, NULL, "Select timer slot 1", cmd_ktd2026_select_timer_slot1),
    SHELL_CMD(timer_slot2, NULL, "Select timer slot 2", cmd_ktd2026_select_timer_slot2),
    SHELL_CMD(timer_slot3, NULL, "Select timer slot 3", cmd_ktd2026_select_timer_slot3),
    SHELL_CMD(timer_slot4, NULL, "Select timer slot 4", cmd_ktd2026_select_timer_slot4),
    SHELL_CMD(reset_registers, NULL, "Reset registers only", cmd_ktd2026_reset_registers_only),
    SHELL_CMD(reset_digital, NULL, "Reset digital only", cmd_ktd2026_reset_digital_only),
    SHELL_CMD(reset_chip, NULL, "Reset entire chip", cmd_ktd2026_reset_chip),
    SHELL_CMD(enable_scl_sda_high, NULL, "Enable: SCL/SDA high", cmd_ktd2026_set_enable_control_scl_sda_high),
    SHELL_CMD(enable_scl_sda_toggle, NULL, "Enable: SCL/SDA toggle", cmd_ktd2026_set_enable_control_scl_sda_toggle),
    SHELL_CMD(enable_scl_high, NULL, "Enable: SCL high", cmd_ktd2026_set_enable_control_scl_high),
    SHELL_CMD(enable_always_on, NULL, "Enable: always on", cmd_ktd2026_set_enable_control_always_on),
    SHELL_CMD(scale_1x, NULL, "Rise/fall scale: 1x", cmd_ktd2026_set_rise_fall_scale_1x),
    SHELL_CMD(scale_2x_slower, NULL, "Rise/fall scale: 2x slower", cmd_ktd2026_set_rise_fall_scale_2x_slower),
    SHELL_CMD(scale_4x_slower, NULL, "Rise/fall scale: 4x slower", cmd_ktd2026_set_rise_fall_scale_4x_slower),
    SHELL_CMD(scale_8x_faster, NULL, "Rise/fall scale: 8x faster", cmd_ktd2026_set_rise_fall_scale_8x_faster),
    SHELL_SUBCMD_SET_END
);

// Flash timing subcommands
SHELL_STATIC_SUBCMD_SET_CREATE(sub_ktd2026_flash,
    SHELL_CMD(set_flash_period, NULL, "Set flash period and ramp mode", cmd_ktd2026_set_flash_period),
    SHELL_CMD(set_flash_on1, NULL, "Set flash ON1 percentage", cmd_ktd2026_set_flash_on1),
    SHELL_CMD(set_flash_on2, NULL, "Set flash ON2 percentage", cmd_ktd2026_set_flash_on2),
    SHELL_SUBCMD_SET_END
);

// LED control subcommands
SHELL_STATIC_SUBCMD_SET_CREATE(sub_ktd2026_led,
    SHELL_CMD(set_led_mode, NULL, "Set LED mode", cmd_ktd2026_set_led_mode),
    SHELL_CMD(set_ramp_times, NULL, "Set ramp rise/fall times", cmd_ktd2026_set_ramp_times),
    SHELL_CMD(set_led_current, NULL, "Set LED current in mA", cmd_ktd2026_set_led_current),
    SHELL_SUBCMD_SET_END
);

// Main subcommand array - combines all commands into a single level
SHELL_STATIC_SUBCMD_SET_CREATE(sub_ktd2026,
    // Basic register commands
    SHELL_CMD(init, NULL, "Initialize KTD2026 device", cmd_ktd2026_init),
    SHELL_CMD(en_rst, NULL, "Write EN_RST register", cmd_ktd2026_en_rst),
    SHELL_CMD(flash_period, NULL, "Write FLASH_PERIOD register", cmd_ktd2026_flash_period),
    SHELL_CMD(flash_on1, NULL, "Write FLASH_ON1 register", cmd_ktd2026_flash_on1),
    SHELL_CMD(flash_on2, NULL, "Write FLASH_ON2 register", cmd_ktd2026_flash_on2),
    SHELL_CMD(channel_ctrl, NULL, "Write CHANNEL_CTRL register", cmd_ktd2026_channel_ctrl),
    SHELL_CMD(ramp_rate, NULL, "Write RAMP_RATE register", cmd_ktd2026_ramp_rate),
    SHELL_CMD(led1_iout, NULL, "Write LED1_IOUT register", cmd_ktd2026_led1_iout),
    SHELL_CMD(led2_iout, NULL, "Write LED2_IOUT register", cmd_ktd2026_led2_iout),
    SHELL_CMD(led3_iout, NULL, "Write LED3_IOUT register", cmd_ktd2026_led3_iout),
    
    // REG0 mode helper commands
    SHELL_CMD(set_reset_mode, NULL, "Set reset mode", cmd_ktd2026_set_reset_mode),
    SHELL_CMD(timer_slot1, NULL, "Select timer slot 1", cmd_ktd2026_select_timer_slot1),
    SHELL_CMD(timer_slot2, NULL, "Select timer slot 2", cmd_ktd2026_select_timer_slot2),
    SHELL_CMD(timer_slot3, NULL, "Select timer slot 3", cmd_ktd2026_select_timer_slot3),
    SHELL_CMD(timer_slot4, NULL, "Select timer slot 4", cmd_ktd2026_select_timer_slot4),
    SHELL_CMD(reset_registers, NULL, "Reset registers only", cmd_ktd2026_reset_registers_only),
    SHELL_CMD(reset_digital, NULL, "Reset digital only", cmd_ktd2026_reset_digital_only),
    SHELL_CMD(reset_chip, NULL, "Reset entire chip", cmd_ktd2026_reset_chip),
    SHELL_CMD(enable_scl_sda_high, NULL, "Enable: SCL/SDA high", cmd_ktd2026_set_enable_control_scl_sda_high),
    SHELL_CMD(enable_scl_sda_toggle, NULL, "Enable: SCL/SDA toggle", cmd_ktd2026_set_enable_control_scl_sda_toggle),
    SHELL_CMD(enable_scl_high, NULL, "Enable: SCL high", cmd_ktd2026_set_enable_control_scl_high),
    SHELL_CMD(enable_always_on, NULL, "Enable: always on", cmd_ktd2026_set_enable_control_always_on),
    SHELL_CMD(scale_1x, NULL, "Rise/fall scale: 1x", cmd_ktd2026_set_rise_fall_scale_1x),
    SHELL_CMD(scale_2x_slower, NULL, "Rise/fall scale: 2x slower", cmd_ktd2026_set_rise_fall_scale_2x_slower),
    SHELL_CMD(scale_4x_slower, NULL, "Rise/fall scale: 4x slower", cmd_ktd2026_set_rise_fall_scale_4x_slower),
    SHELL_CMD(scale_8x_faster, NULL, "Rise/fall scale: 8x faster", cmd_ktd2026_set_rise_fall_scale_8x_faster),
    
    // Flash timing commands
    SHELL_CMD(set_flash_period, NULL, "Set flash period and ramp mode", cmd_ktd2026_set_flash_period),
    SHELL_CMD(set_flash_on1, NULL, "Set flash ON1 percentage", cmd_ktd2026_set_flash_on1),
    SHELL_CMD(set_flash_on2, NULL, "Set flash ON2 percentage", cmd_ktd2026_set_flash_on2),
    
    // LED control commands
    SHELL_CMD(set_led_mode, NULL, "Set LED mode", cmd_ktd2026_set_led_mode),
    SHELL_CMD(set_ramp_times, NULL, "Set ramp rise/fall times", cmd_ktd2026_set_ramp_times),
    SHELL_CMD(set_led_current, NULL, "Set LED current in mA", cmd_ktd2026_set_led_current),
    
    // Help command
    SHELL_CMD(help, NULL, "Show help", cmd_ktd2026_help),
    SHELL_SUBCMD_SET_END
);

// Register the main command
SHELL_CMD_REGISTER(ktd2026, &sub_ktd2026, "KTD2026 LED driver commands", cmd_ktd2026_help);