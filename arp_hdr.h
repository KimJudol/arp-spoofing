#include <stdio.h>
#include <stdint.h>

#define MAC_LEN 6
#define IP_LEN 4

typedef struct {
    uint16_t HType;
    uint16_t PType;
    uint8_t HLen;
    uint8_t PLen;
    uint16_t Oper;
    uint8_t smac[MAC_LEN];
    uint8_t sip[IP_LEN];
    uint8_t tmac[MAC_LEN];
    uint8_t tip[IP_LEN];
} arp_hdr;