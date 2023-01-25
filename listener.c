#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define RECV_MAX_SIZE 0xffff
#define BUFFER_SIZE 0xffff
#define DESTINATION_IP "127.0.0.1"
#define DESTINATION_PORT 9999
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0808

typedef struct
{
	uint64_t source_mac: 48;
	uint64_t destination_mac: 48;
	uint16_t ether_type;
} __attribute__((packed)) ETHER_HEADER;

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

void data_handler(char *data, int len)
{
	printf("[*] %-5d ", len);
	ETHER_HEADER *ether_header = (ETHER_HEADER *)data;
	switch (ntohs(ether_header -> ether_type))
	{
		case (ETHERTYPE_IP): {
			printf("IP ");
			break;
		}
		case (ETHERTYPE_ARP): {
			printf("ARP ");
			break;
		}
		default: {
			printf("Unk ");
		}
	}
	printf("\n");
}

int main()
{
	/* Create connection and receive data from tgt server */
	int fd = -1;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
	{
		printf("[x] Create socket error\n");
		return 0;
	}
	printf("[+] Create socket\n");
	// Address //
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DESTINATION_PORT);
	server_addr.sin_addr.s_addr = inet_addr(DESTINATION_IP);
	// Connect to server //
	if (connect(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0)
	{
		printf("[x] Connect error\n");
		return 0;
	}
	printf("[+] Connect to %s:%d\n", DESTINATION_IP, DESTINATION_PORT);
	// Receive data //
	for (;;)
	{
		char *data = (char *)malloc(BUFFER_SIZE * sizeof(char));
		memset(data, 0, BUFFER_SIZE);
		int len = recv(fd, data, RECV_MAX_SIZE, 0);
		if (len < 0)
		{
			printf("[!] Receive error(ignore)\n");
			free(data);
			continue;
		}
		data_handler(data, len);
		free(data);
	}

	return 0;
}
