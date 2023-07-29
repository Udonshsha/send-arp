#include "cpp.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)

char ip[INET_ADDRSTRLEN];

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
int i=2;

	while(1){
		
		if( i>= argc){
			break;
		}
		
		if(argc%2 != 0){
			fprintf(stderr,"please input cupple ip\n");
			break;
		}
		
		char D_MAC[Mac::SIZE];
		char* dev = argv[1];
		char errbuf[PCAP_ERRBUF_SIZE];

		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		getIP(argv[1], ip);
    
		EthArpPacket packet;

		packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
		packet.eth_.smac_ = Mac(get_mac_address().c_str());
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request); 

		packet.arp_.smac_ = Mac(get_mac_address().c_str());
		packet.arp_.sip_ = htonl(Ip(ip));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); 
		packet.arp_.tip_ = htonl(Ip(argv[i]));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	
		printf("IP: %s\n", ip);
		printf("MAC address : [%s]\n", get_mac_address().c_str());
	
		while (true) {
			struct pcap_pkthdr* header;
			const u_char* reply_packet;
			int result = pcap_next_ex(handle, &header, &reply_packet);
			if (result != 1) {
				continue;
			}

			EthArpPacket* reply = (EthArpPacket*)reply_packet;

			if (ntohs(reply->eth_.type_) == EthHdr::Arp && ntohs(reply->arp_.op_) == ArpHdr::Reply &&
				reply->arp_.sip_ == packet.arp_.tip_ && reply->arp_.tip_ == packet.arp_.sip_) {
				strcpy(D_MAC, std::string(reply->arp_.smac_).c_str());
				printf("Found target MAC address: %s\n", std::string(reply->arp_.smac_).c_str());
				break;
			}
		}

		EthArpPacket packet_2;

		packet.eth_.dmac_ = Mac(D_MAC);
		packet.eth_.smac_ = Mac(get_mac_address().c_str());
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply); 

		packet.arp_.smac_ = Mac(get_mac_address().c_str());
		packet.arp_.sip_ = htonl(Ip(argv[i+1]));
		packet.arp_.tmac_ = Mac(D_MAC); 
		packet.arp_.tip_ = htonl(Ip(argv[i]));

		int ras = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		if (ras != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", ras, pcap_geterr(handle));
		}
		pcap_close(handle);
		i=i+2;
	}
    return 0;
}
