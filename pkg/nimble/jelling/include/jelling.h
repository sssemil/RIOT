#ifndef JELLING_H
#define JELLING_H

#include "net/gnrc/netif.h"
#include "net/gnrc/pktbuf.h"
#include "net/ble.h"

#ifndef JELLING_ADVERTISING_ENABLE_DFLT
#define JELLING_ADVERTISING_ENABLE_DFLT                 1
#endif

#ifndef JELLING_ADVERTISING_VERBOSE_DFLT
#define JELLING_ADVERTISING_VERBOSE_DFLT                0
#endif

#ifndef JELLING_ADVERTISING_BLOCK_ICMP_DFLT
#define JELLING_ADVERTISING_BLOCK_ICMP_DFLT             0
#endif

/**
 * @brief   Number of advertising events that should be sent
 *          before advertising ends and
 *          a BLE_GAP_EVENT_ADV_COMPLETE event is reported.
 *          Specify 0 for no limit.
 */
#ifndef JELLING_ADVERTISING_EVENTS
#define JELLING_ADVERTISING_EVENTS                      3
#endif

/**
 * @brief   The duration of the advertisement procedure. On expiration, the
 *          procedure ends and a BLE_GAP_EVENT_ADV_COMPLETE event is reported.
 *          Units are 10 milliseconds. Specify 0 for no expiration.
 */
#ifndef JELLING_ADVERTISING_DURATION
#define JELLING_ADVERTISING_DURATION                    0
#endif

#ifndef JELLING_SCANNER_ENABLE_DFLT
#define JELLING_SCANNER_ENABLE_DFLT                     1
#endif

#ifndef JELLING_SCANNER_VERBOSE_DFLT
#define JELLING_SCANNER_VERBOSE_DFLT                    0
#endif

#ifndef JELLING_SCANNER_ITVL
#define JELLING_SCANNER_ITVL                            BLE_GAP_SCAN_FAST_INTERVAL_MIN
#endif

#ifndef JELLING_SCANNER_WINDOW
#define JELLING_SCANNER_WINDOW                          BLE_GAP_SCAN_FAST_WINDOW
#endif

#ifndef JELLING_SCANNER_DURATION
#define JELLING_SCANNER_DURATION                        0
#endif

#ifndef JELLING_SCANNER_PERIOD
#define JELLING_SCANNER_PERIOD                          0
#endif

#ifndef JELLING_SCANNER_FILTER_SIZE
#define JELLING_SCANNER_FILTER_SIZE                     3
#endif

/**
 * @brief   Enable or disable duplicate detection. If disabled, the BLE controller
 *          still filters for duplicates! In crowded areas this system tries to
 *          filter when the controller fails (due to high traffic).
 *
 *          Note: If disabled: duplicate detection will not be compiled into
 *                jelling!
 */
#ifndef JELLING_DUPLICATE_DETECTION_FEATURE_ENABLE
#define JELLING_DUPLICATE_DETECTION_FEATURE_ENABLE              0
#endif

#if JELLING_DUPLICATE_DETECTION_FEATURE_ENABLE
/**
 *  @brief  Default value whether duplicate detection should be automatically
 *          activated
 */
#ifndef JELLING_DUPLICATE_DETECTION_ACTIVATION_DFTL
#define JELLING_DUPLICATE_DETECTION_ACTIVATION_DFTL     0
#endif
#endif

/**
 *  @brief  Manufacturer ID used for advertising. Don't use any of those listed here:
 *          https://www.bluetooth.com/de/specifications/assigned-numbers/company-identifiers/
 */
#ifndef VENDOR_ID_1
#define VENDOR_ID_1             (0xFE)
#endif
#ifndef VENDOR_ID_2
#define VENDOR_ID_2             (0xED)
#endif

/**
 * @brief   Status types of the NimBLE jelling module
 */
typedef enum {
    JELLING_INIT_ERROR = -2,
    JELLING_RUNTIME_ERROR = -1,
    JELLING_STOPPED = 0,         /**< network connector is stopped */
    JELLING_RUNNING = 1
} jelling_status_t;

typedef struct {
    uint8_t addr[BLE_ADDR_LEN];
    bool empty;
} filter_entry_t;

typedef struct {
    bool advertiser_enable;
    bool advertiser_verbose;
    bool advertiser_block_icmp;
    bool scanner_enable;
    bool scanner_verbose;
    bool scanner_filter_empty;
    filter_entry_t scanner_filter[JELLING_SCANNER_FILTER_SIZE];
    bool duplicate_detection_enable;
} jelling_config_t;

int jelling_init(gnrc_netif_t *netif, gnrc_nettype_t nettype);
void jelling_start(void);
void jelling_stop(void);

int jelling_send(gnrc_pktsnip_t *pkt);

void jelling_load_default_config(void);
jelling_config_t* jelling_get_config(void);
int jelling_filter_add(char *addr);
void jelling_filter_clear(void);

void jelling_print_config(void);
void jelling_print_info(void);

#endif /* JELLING_H */