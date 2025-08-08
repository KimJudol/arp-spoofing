LDLIBS += -lpcap

all: arp-spoofing

report-send-arp: arp-spoofing.o
	g++ -o arp-spoofing arp-spoofing.o -lpcap

report-send-arp.o: arp_hdr.h eth_hdr.h arp-spoofing.cpp
	g++ -c -o arp-spoofing.o arp-spoofing.cpp

clean:
	rm -f arp-spoofing *.o