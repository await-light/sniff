#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#define RECV_MAX_SIZE 0xffff
#define MAX_LISTENERS 100
#define BUFFER_SIZE 0xffff
#define IP "0.0.0.0"
#define IPTYPE_TCP 6

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
	uint32_t sequence_number;
	uint32_t acknowledgment_number;
	uint8_t reserved: 4;
	uint8_t header_length: 4;
	uint8_t flags;
    uint16_t window_size;
    uint16_t header_checksum;
    uint16_t urgent_pointer;
} __attribute__((packed)) TCP_HEADER;

int listenersnumber = 0;
// Save socket fd //
int listenerslist[MAX_LISTENERS];

void *sniff(void *args)
{
	/* Create sniffing socket */
	int fd = -1;
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
	{
		printf("[!] Create sniffing socket error: sniffing service " \
			"will stop and programme will not work correctly\n");
		return 0;
	}
	printf("[+] Create sniffing socket\n");

	/* Receive data */
	printf("[+] Start sniffing\n");
	for (;;)
	{
		struct sockaddr srcaddr;
		int srcaddr_size = sizeof(struct sockaddr);
		memset(&srcaddr, 0, srcaddr_size);
		// Data buffer //
		char *data = (char *)malloc(BUFFER_SIZE * sizeof(char));
		memset(data, 0, BUFFER_SIZE);
		size_t recvlen = recvfrom(fd, data, BUFFER_SIZE, 0, &srcaddr, (socklen_t *)&srcaddr_size);
		/*
		Issue:
		If this computer sends LAN data to listener,
		the size of data sent to listen will increase the size of IP and TCP header
		and this computer sniffs this bigger packet, then sends to listener
		So it's not good to sniff data sent to listener 
		*/
		uint32_t data_source_ip, data_destination_ip;
		uint16_t data_source_port, data_destination_port;
		ETHER_HEADER *ether_header = (ETHER_HEADER *)data;
		if (ntohs(ether_header -> ether_type) == ETHERTYPE_IP)
		{
			IP_HEADER *ip_header = (IP_HEADER *)(data + sizeof(ETHER_HEADER));
			data_source_ip = ntohl(ip_header -> source_ip_address);
			data_destination_ip = ntohl(ip_header -> destination_ip_address);
			if ((ip_header -> protocol) == IPTYPE_TCP)
			{
				TCP_HEADER *tcp_header = (TCP_HEADER *)(data + sizeof(ETHER_HEADER) + sizeof(IP_HEADER));
				data_source_port = ntohs(tcp_header -> source_port);
				data_destination_port = ntohs(tcp_header -> destination_port);
			}
		}
		// If data_destination_ip:port or data_source_ip:port in listeners list, stop sending //
		int inlist = 0;
		for (int c = 0; c < listenersnumber; ++c)
		{	
			struct sockaddr remoteaddr;
			struct sockaddr_in *remoteaddr_in;
			socklen_t sizeofaddr = sizeof(struct sockaddr);
			getpeername(listenerslist[c], &remoteaddr, &sizeofaddr);
			remoteaddr_in = (struct sockaddr_in *)&remoteaddr;
			uint32_t listener_ip = ntohl(remoteaddr_in -> sin_addr.s_addr);
			uint16_t listener_port = ntohs(remoteaddr_in -> sin_port);
			if ((data_destination_ip == listener_ip && data_destination_port == listener_port) || \
				(data_source_ip == listener_ip && data_source_port == listener_port))
			{
				inlist = 1;
				break;
			}
		}
		if (inlist)
		{
			continue;
		}

		// Broadcast //
		for (int c = 0; c < listenersnumber; ++c)
		{
			if (send(listenerslist[c], data, recvlen, 0) < 0)
			{
				for (int i = c; i < listenersnumber; ++i)
				{
					listenerslist[i] = listenerslist[i + 1]; 
				}
				listenersnumber--;
				printf("[+] Disconnect(index:%d), left:%d\n", c, listenersnumber);
			}
		}
		free(data);
	}
	close(fd);
}

int main(int argc, char **argv)
{
	/* Setup sniffing programme */
	pthread_t sniffth;
	pthread_create(&sniffth, 0, sniff, 0);
	// give sniffing programme 1 second to get ready //
	sleep(1);

	/*
	1. Get the port of the service 
	*/
	uint16_t port = -1;
	sscanf(argv[1], "%hd", &port);
	if (port >= 0xffff || port <= 0)
	{
		printf("[x] You gave a wrong port\n");
		return 0;
	}

	/*
	1. Create Tcp socket
		- create
		- bind
		- max listeners
	2. Statu of listening
		- accept
	3. Add listener to list of listeners
	(4. included by function `sniff`) Send data to listeners in list
	*/
	int tcpfd = -1;
	struct sockaddr_in address;
	memset(&address, 0, sizeof(struct sockaddr_in));
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	address.sin_addr.s_addr = inet_addr(IP);
	tcpfd = socket(AF_INET, SOCK_STREAM, 0);
	if (tcpfd == -1)
	{
		printf("[x] Create listener error\n");
		return 0;
	}
	printf("[+] Create listener socket\n");
	// Introduction: programme might quit when client is closed because of SIGPIPE signal! //
	// struct sigaction sa;
	// sa.sa_handler = SIG_IGN;
	// sa.sa_flags = 0;
	// if ((sigemptyset(&sa.sa_mask) < 0) || (sigaction(SIGPIPE, &sa, 0) < 0))
	if (signal(SIGPIPE, SIG_IGN) < 0)
	{
		printf("[!] Set SIGPIPE handler, the programme will quit when client is closed\n");
	}
	printf("[+] Set SIGPIPE handler\n");
	if (bind(tcpfd, (struct sockaddr *)&address, sizeof(struct sockaddr)) < 0)
	{
		printf("[x] Bind error\n");
		return 0;
	}
	printf("[+] Bind to port: %hd\n", port);
	if (listen(tcpfd, MAX_LISTENERS) < 0)
	{
		printf("[x] Set maximum number the listeners error\n");
		return 0;
	}
	printf("[+] Set max listeners: %d\n", MAX_LISTENERS);
	for (;;)
	{
		int new_fd;
		struct sockaddr raddress;
		socklen_t addrlen = sizeof(struct sockaddr);
		new_fd = accept(tcpfd, &raddress, &addrlen);
		if (new_fd < 0)
		{
			printf("[x] Accept error(igrone)\n");
			continue;
		}
		// Add to listeners list //
		listenerslist[listenersnumber] = new_fd;
		listenersnumber++;

		struct sockaddr_in *new_address = (struct sockaddr_in *)(&raddress);
		uint8_t *ipp = (uint8_t *)&(((struct in_addr *)&(new_address -> sin_addr)) -> s_addr);
		uint16_t portv = ntohs((uint16_t)(new_address -> sin_port));
		printf("[+] Accept: %d.%d.%d.%d:%hu\n", *ipp, *(ipp + 1), *(ipp + 2), *(ipp + 3), portv);
	}

	return 0;
}
