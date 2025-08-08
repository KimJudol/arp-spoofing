#include <stdio.h>
#include <stdint.h>

#define ETH_LEN 6

typedef struct {
        uint8_t dmac[ETH_LEN];
        uint8_t smac[ETH_LEN];
		uint16_t ethType;
} eth_hdr;
