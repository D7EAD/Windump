#include <windows.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <thread>
#include "windivert.h"

#define INET6_ADDRSTRLEN    45
#define ntohl(x)            WinDivertHelperNtohl(x)
#define ntohs(x)            WinDivertHelperNtohs(x)

void startSniff(void* open);

int main(int argc, const char* argv[]) {
	std::string filterList; 
	if (argc < 2) { filterList = "true"; }
	else {
		for (int i = 1; i < argc; i++) {
			filterList += argv[i]; filterList += " ";
		}
	}
	HANDLE open = WinDivertOpen(filterList.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
	if (open == INVALID_HANDLE_VALUE) {
		std::cout << "Error opening WinDivert!" << std::endl;
		exit(1);
	}
	std::cout << "Filter in-use: " << filterList;
	_beginthread(startSniff, 0, &open);
	while (true) {} // MT
}

void startSniff(void* open) {
	unsigned char packet[WINDIVERT_MTU_MAX];
	WINDIVERT_ADDRESS recv_addr;
	unsigned int packet_len, send_len;
	PVOID payload = NULL; std::string str_payload;
	UINT payload_len;
	UINT32 src_addr[4], dst_addr[4];
	char src_str[INET6_ADDRSTRLEN + 1], dst_str[INET6_ADDRSTRLEN + 1];
	PWINDIVERT_IPHDR ip_header = NULL;
	PWINDIVERT_IPV6HDR ip6_header = NULL;
	PWINDIVERT_UDPHDR udp_header = NULL;
	PWINDIVERT_TCPHDR tcp_header = NULL;
	PWINDIVERT_ICMPHDR icmp_header = NULL;
	PWINDIVERT_ICMPV6HDR icmpv6_header = NULL;
	while (true) {
		WinDivertRecv(*(HANDLE*)open, packet, sizeof(packet), &packet_len, &recv_addr);
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ip6_header, NULL, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, &payload, &payload_len, NULL, NULL);
		if (payload != NULL) {
			str_payload = (char*)payload;
			str_payload.erase(std::remove(str_payload.begin(), str_payload.end(), '\n'), str_payload.end()); // remove newlines 
			str_payload.erase(std::remove(str_payload.begin(), str_payload.end(), '\t'), str_payload.end()); // remove tabs 
			str_payload.erase(std::remove(str_payload.begin(), str_payload.end(), '\r'), str_payload.end()); // remove returns
			str_payload.erase(std::remove(str_payload.begin(), str_payload.end(), ' '),  str_payload.end()); // remove spaces
			if (str_payload == "") { str_payload = "(null)"; }
		}
		else { str_payload = "(null)"; }
		if (ip_header != NULL) {
			WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr), src_str, sizeof(src_str));
			WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr), dst_str, sizeof(dst_str));
			printf("\n| [IPv4] : TTL %u, TOS 0x%.2X, id %u, len %u, hdrlen %u, off %u\n|\t%s -> %s\n", ip_header->TTL, ip_header->TOS, ntohs(ip_header->Id), ntohs(ip_header->Length), ip_header->HdrLength, ntohs(ip_header->FragOff0), src_str, dst_str);
			if (tcp_header != NULL) {
				printf("|\t| [TCP]"
					"\n|\t|\t| Ports=%u->%u"
					"\n|\t|\t| SeqNum=%u"
					"\n|\t|\t| AckNum=%u"
					"\n|\t|\t| HdrLength=%u"
					"\n|\t|\t| Flags:"
					"\n|\t|\t|\tUrg=%u, UrgPtr=%u, Ack=%u, Psh=%u, Rst=%u, Syn=%u, Fin=%u"
					"\n|\t|\t| Window=%u"
					"\n|\t|\t| Checksum=0x%.4X"
					"\n|\t|\t| %s",
					ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort),
					ntohl(tcp_header->SeqNum), ntohl(tcp_header->AckNum),
					tcp_header->HdrLength, tcp_header->Urg, ntohs(tcp_header->UrgPtr),
					tcp_header->Ack, tcp_header->Psh, tcp_header->Rst,
					tcp_header->Syn, tcp_header->Fin, ntohs(tcp_header->Window),
					ntohs(tcp_header->Checksum), str_payload.c_str());
			}
			if (udp_header != NULL) {
				printf("|\t| [UDP]"
					"\n|\t|\t| Ports: %u->%u"
					"\n|\t|\t| Length=%u"
					"\n|\t|\t| Checksum=0x%.4X"
					"\n|\t|\t| %s",
					ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort),
					ntohs(udp_header->Length), ntohs(udp_header->Checksum),
					str_payload.c_str());
			}
			if (icmp_header != NULL) {
				printf("|\t| [ICMP]"
					"\n|\t|\t| Type=%u"
					"\n|\t|\t| Code=%u"
					"\n|\t|\t| Checksum=0x%.4X"
					"\n|\t|\t| Body=0x%.8X",
					icmp_header->Type, icmp_header->Code,
					ntohs(icmp_header->Checksum), ntohl(icmp_header->Body));
			}
		}
		else if (ip6_header != NULL) {
			WinDivertHelperNtohIPv6Address(ip6_header->SrcAddr, src_addr);
			WinDivertHelperNtohIPv6Address(ip6_header->DstAddr, dst_addr);
			WinDivertHelperFormatIPv6Address(src_addr, src_str, sizeof(src_str));
			WinDivertHelperFormatIPv6Address(dst_addr, dst_str, sizeof(dst_str));
			printf("\n| [IPv6] : len %u, nxthdr %u, hoplim %u\n|\t%s -> %s\n", ntohs(ip6_header->Length), ip6_header->NextHdr, ip6_header->HopLimit, src_str, dst_str);
			if (tcp_header != NULL) {
				printf("|\t| [TCP]"
					"\n|\t|\t| Ports: %u->%u"
					"\n|\t|\t| SeqNum=%u"
					"\n|\t|\t| AckNum=%u"
					"\n|\t|\t| HdrLength=%u"
					"\n|\t|\t| Flags:"
					"\n|\t|\t|\tUrg=%u, UrgPtr=%u, Ack=%u, Psh=%u, Rst=%u, Syn=%u, Fin=%u"
					"\n|\t|\t| Window=%u"
					"\n|\t|\t| Checksum=0x%.4X"
					"\n|\t|\t| %s",
					ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort),
					ntohl(tcp_header->SeqNum), ntohl(tcp_header->AckNum),
					tcp_header->HdrLength, tcp_header->Urg, ntohs(tcp_header->UrgPtr),
					tcp_header->Ack, tcp_header->Psh, tcp_header->Rst,
					tcp_header->Syn, tcp_header->Fin, ntohs(tcp_header->Window),
					ntohs(tcp_header->Checksum), str_payload.c_str());
			}
			if (udp_header != NULL) {
				printf("|\t| [UDP]"
					"\n|\t|\t| Ports: %u->%u"
					"\n|\t|\t| Length=%u"
					"\n|\t|\t| Checksum=0x%.4X"
					"\n|\t|\t| %s",
					ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort),
					ntohs(udp_header->Length), ntohs(udp_header->Checksum),
					str_payload.c_str());
			}
			if (icmpv6_header != NULL) {
				printf("|\t| [ICMPv6]"
					"\n|\t|\t| Type=%u"
					"\n|\t|\t| Code=%u"
					"\n|\t|\t| Checksum=0x%.4X"
					"\n|\t|\t| Body=0x%.8X",
					icmpv6_header->Type, icmpv6_header->Code,
					ntohs(icmpv6_header->Checksum), ntohl(icmpv6_header->Body));
			}
		}
		WinDivertSend(*(HANDLE*)open, packet, sizeof(packet), &send_len, &recv_addr);
	}
}