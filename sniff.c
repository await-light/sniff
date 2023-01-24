#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define BUFFSIZE 65535
#define MACBUFFSIZE 20
#define ARP_OPCODE_REQUEST 1
#define ARP_OPCODE_REPLY 2
#define ICMP_TYPE_REQUEST 8
#define ICMP_TYPE_REPLY 0
#define IPTYPE_UDP 17
#define IPTYPE_TCP 6 
#define IPTYPE_ICMP 1

typedef struct ether_header ETHER_HEADER;

typedef struct
{
	char type[BUFFSIZE];
	char des[BUFFSIZE];
} OUTPUT;

typedef struct
{
	uint8_t header_length: 4;
	uint8_t version: 4;
	uint8_t type_of_serive;
	uint16_t total_length;
	uint16_t id;
	uint16_t fragmentfation_offset: 13;
	uint16_t flags: 3;
	uint8_t time_to_live;
	uint8_t protocol;
	uint16_t header_checksum;
	uint32_t source_ip_address;
	uint32_t destination_ip_address;
} __attribute__((packed)) IP_HEADER;

typedef struct
{
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t length;
	uint16_t header_checksum;
} __attribute__((packed)) UDP_HEADER;

typedef struct
{
	uint16_t source_port;
	uint16_t destination_port;
	uint32_t sequence_number;
	uint32_t acknowledgment_number;
	uint8_t reserved: 4;
	uint8_t header_length: 4;
	uint8_t fin: 1;
	uint8_t syn: 1;
	uint8_t rst: 1;
	uint8_t psh: 1;
	uint8_t ack: 1;
	uint8_t urg: 1;
	uint8_t ece: 1;
	uint8_t cwr: 1;
    uint16_t window_size;
    uint16_t header_checksum;
    uint16_t urgent_pointer;
} __attribute__((packed)) TCP_HEADER;

typedef struct
{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint64_t source_mac: 48;
	uint32_t source_ip;
	uint64_t destination_mac: 48;
	uint32_t destination_ip;
} __attribute__((packed)) ARP_HEADER;

typedef struct
{
	uint8_t type;
	uint8_t code;
	uint16_t header_checksum;
	uint16_t id;
	uint16_t sequence_number;
} __attribute__((packed)) ICMP_HEADER;

void sprintf_ip_int2string(char *ip_string, void *intip)
{
	uint8_t *p = (uint8_t *)intip;
	sprintf(ip_string, "%d.%d.%d.%d", *p, *(p + 1), *(p + 2), *(p + 3));
}

void sprintf_mac_string2format(char *mac_string, char ether_host[])
{
	sprintf(mac_string, "%02x:%02x:%02x:%02x:%02x:%02x",
		ether_host[0],
		ether_host[1],
		ether_host[2],
		ether_host[3],
		ether_host[4],
		ether_host[5]
	);
}

int main(int argc, char argv[])
{
	/* Create socket */
	int fd = -1;
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd == -1)
	{
		printf("Permission Denied.\n");
		return 0;
	}

	/* Receive loop */	
	for (;;)
	{
		/* Received data buffer and output buffer */
		char data[BUFFSIZE];
		struct sockaddr saddr;
		int saddr_size = sizeof(saddr);
		OUTPUT output;
		memset(output.type, 0, BUFFSIZE);
		memset(output.des, 0, BUFFSIZE);

		/* Receive data and format */
		recvfrom(fd, data, BUFFSIZE, 0, &saddr, (socklen_t *)&saddr_size);
		ETHER_HEADER *eth = (ETHER_HEADER *)data;

		/* Get mac source and destination */
		char sourcemac[MACBUFFSIZE] = "";
		char destinationmac[MACBUFFSIZE] = "";
		sprintf_mac_string2format(sourcemac, eth -> ether_shost);
		sprintf_mac_string2format(destinationmac, eth -> ether_dhost);
		strcat(output.des, "mac:");
		strcat(output.des, sourcemac);
		strcat(output.des, "->");
		strcat(output.des, destinationmac);
		strcat(output.des, "; ");

		/* Judge what protocol is used */
		switch (ntohs(eth -> ether_type))
		{
			/* IP protocol */
			case (ETHERTYPE_IP): {
				IP_HEADER *ipheader = (IP_HEADER *)(data + sizeof(ETHER_HEADER));

				/* Int IP to String */
				char sourceip[32], destinationip[32];
				sprintf_ip_int2string(sourceip, &(ipheader -> source_ip_address));
				sprintf_ip_int2string(destinationip, &(ipheader -> destination_ip_address));
				strcat(output.type, "IP");
				strcat(output.des, "ip:");
				strcat(output.des, sourceip);
				strcat(output.des, "->");
				strcat(output.des, destinationip);
				strcat(output.des, "; ");

				/* Protocol type of IP */
				switch (ipheader -> protocol)
				{
					/* ICMP Protocol */
					case (IPTYPE_ICMP): {
						ICMP_HEADER *icmp_header = (ICMP_HEADER *)(data + sizeof(ETHER_HEADER) + sizeof(IP_HEADER));

						/* ICMP type: request or reply? */
						strcat(output.des, "type:");
						switch (icmp_header -> type)
						{
							case (ICMP_TYPE_REQUEST): {
								strcat(output.des, "request");
								break;
							}
							case (ICMP_TYPE_REPLY): {
								strcat(output.des, "reply");
								break;
							}
							default: {
								char strtype[8];
								sprintf(strtype, "%d", icmp_header -> type);
								strcat(output.des, strtype);
							}
						}

						/* Add type information */
						strcat(output.type, "/ICMP");
						break;
					}
					/* UDP Protocol */
					case (IPTYPE_UDP): {
						UDP_HEADER *udp_header = (UDP_HEADER *)(data + sizeof(ETHER_HEADER) + sizeof(IP_HEADER));
						
						/* Source port and destination port */
						char sourceport[6], destinationport[6];
						sprintf(sourceport, "%d", ntohs(udp_header -> source_port));
						sprintf(destinationport, "%d", ntohs(udp_header -> destination_port));
						strcat(output.des, "port:");
						strcat(output.des, sourceport);
						strcat(output.des, "->");
						strcat(output.des, destinationport);
						strcat(output.des, "; ");

						/* Add type information */
						strcat(output.type, "/UDP");
						break;
					}
					/* TCP Protocol */
					case (IPTYPE_TCP): {
						TCP_HEADER *tcp_header = (TCP_HEADER *)(data + sizeof(ETHER_HEADER) + sizeof(IP_HEADER));
						
						/* Source port and destination */
						char sourceport[6], destinationport[6];
						sprintf(sourceport, "%d", ntohs(tcp_header -> source_port));
						sprintf(destinationport, "%d", ntohs(tcp_header -> destination_port));
						strcat(output.des, "port:");
						strcat(output.des, sourceport);
						strcat(output.des, "->");
						strcat(output.des, destinationport);
						strcat(output.des, "; ");

						/* Flags */
						strcat(output.des, "flags:");
						int n = 0; /* The number of flags */
						if (tcp_header -> fin)
						{
							if (n != 0) {strcat(output.des, ",");}
							strcat(output.des, "fin");
							n++;
						}
						if (tcp_header -> syn)
						{
							if (n != 0) {strcat(output.des, ",");}
							strcat(output.des, "syn");
							n++;
						}
						if (tcp_header -> rst)
						{
							if (n != 0) {strcat(output.des, ",");}
							strcat(output.des, "rst");
							n++;
						}
						if (tcp_header -> psh)
						{
							if (n != 0) {strcat(output.des, ",");}
							strcat(output.des, "psh");
							n++;
						}
						if (tcp_header -> ack)
						{
							if (n != 0) {strcat(output.des, ",");}
							strcat(output.des, "ack");
							n++;
						}
						if (tcp_header -> urg)
						{
							if (n != 0) {strcat(output.des, ",");}
							strcat(output.des, "urg");
							n++;
						}
						if (tcp_header -> ece)
						{
							if (n != 0) {strcat(output.des, ",");}
							strcat(output.des, "ece");
							n++;
						}
						if (tcp_header -> cwr)
						{
							if (n != 0) {strcat(output.des, ",");}
							strcat(output.des, "cwr");
							n++;
						}
						if (n == 0)
						{
							strcat(output.des, "nul");
						}
						strcat(output.des, "; ");

						/* Sequence number */
						char sequencenumber[10];
						sprintf(sequencenumber, "%u", ntohl(tcp_header -> sequence_number));
						strcat(output.des, "seq:");
						strcat(output.des, sequencenumber);
						strcat(output.des, "; ");

						/* Acknowledgment number */
						if (tcp_header -> ack)
						{
							char acknowledgmentnumber[10];
							sprintf(acknowledgmentnumber, "%u", ntohl(tcp_header -> acknowledgment_number));
							strcat(output.des, "ack:");
							strcat(output.des, acknowledgmentnumber);
							strcat(output.des, "; ");
						}

						/* Add type information */
						strcat(output.type, "/TCP");
						break;
					}
					/* Unknown Protocol */
					default: {
						strcat(output.type, "/Unk");
					}
				}
				break;
			}

			/* ARP protocol */
			case (ETHERTYPE_ARP): {
				ARP_HEADER *arp_header = (ARP_HEADER *)(data + sizeof(ETHER_HEADER));

				/* Add type */
				strcat(output.type, "ARP");

				/* Int IP to String */
				char sourceip[32], destinationip[32];
				sprintf_ip_int2string(sourceip, &(arp_header -> source_ip));
				sprintf_ip_int2string(destinationip, &(arp_header -> destination_ip));
				strcat(output.des, "ip:");
				strcat(output.des, sourceip);
				strcat(output.des, "->");
				strcat(output.des, destinationip);
				strcat(output.des, "; ");

				/* Operation code */
				strcat(output.des, "opcode:");
				switch (ntohs(arp_header -> opcode))
				{
					case (ARP_OPCODE_REQUEST): {
						strcat(output.des, "request");
						break;
					}
					case (ARP_OPCODE_REPLY): {
						strcat(output.des, "reply");
						break;
					}
					default: {
						char stropcode[10];
						sprintf(stropcode, "%d", ntohs(arp_header -> opcode));
						strcat(output.des, stropcode);
					}
				}
				strcat(output.des, "; ");
				break;
			}

			/* Unknown protocol or haven't provided method */
			default: {
				strcat(output.type, "Unk ");
			}
		}

		/* Print output */
		printf("%-10s | %s\n", output.type, output.des);
	}

	return 0;
}
