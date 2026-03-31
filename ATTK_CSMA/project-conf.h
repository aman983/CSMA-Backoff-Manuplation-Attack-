#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define UART0_CONF_BAUD_RATE 115200
/* CSMA Backoff parameters */
#define CSMA_CONF_MIN_BE               3   // smaller → more aggressive
#define CSMA_CONF_MAX_BE               5   // limit exponential growth

#define CSMA_CONF_MAX_BACKOFF          5   // fewer backoffs allowed
#define CSMA_CONF_MAX_FRAME_RETRIES    7   // fewer retries

#undef IEEE802154_CONF_DEFAULT_CHANNEL
#define IEEE802154_CONF_DEFAULT_CHANNEL 14
#undef IEEE802154_CONF_PANID
#define IEEE802154_CONF_PANID 0xABDF

#define LOG_CONF_LEVEL_MAC LOG_LEVEL_INFO
#endif
