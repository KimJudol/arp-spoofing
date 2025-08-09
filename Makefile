CXXFLAGS := -Wall -O2 -pthread
LDFLAGS := -pthread
LDLIBS += -lpcap


all: arp-spoofing

arp-spoofing: arp-spoofing.o
	g++ $(CXXFLAGS) $(LDFLAGS) -o arp-spoofing arp-spoofing.o -lpcap

arp-spoofing.o: arp_hdr.h eth_hdr.h arp-spoofing.cpp
	g++ $(CXXFLAGS) -c -o arp-spoofing.o arp-spoofing.cpp

clean:
	rm -f arp-spoofing *.o