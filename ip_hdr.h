#include <stdio.h>
#include <stdint.h>

#define IP_LEN 4

typedef struct {
	uint8_t ver_ihl;
	uint8_t dscp_ecn;
	uint16_t total_len;
	uint16_t identification;
	uint16_t flags_fragment_offset;
	uint8_t T2L;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t dst_ip[IP_LEN];
	uint8_t src_ip[IP_LEN];
} ip_hdr;
