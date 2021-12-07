#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include "addropper.h"

int main(int arc, char ** argv) {
	int fd = get_socket();
	if (fd < 0) return 1;
	
	struct sockaddr_in * sender = malloc(sizeof(struct sockaddr_in));
	char * buf = malloc(MAX_DNS_SIZE);
	dns_packet * pkt = malloc(sizeof(dns_packet));
	u8 len_sender = sizeof(sender);
	
	// get a DNS server
	struct sockaddr_in dns_server;
	get_dns_server(&dns_server);
	
	// 2^16 (for Transaction IDs) * 8 Byte Pointer = 524288
	// Have a pointer to a mapping for every Transaction ID.
	sender_packet_map * dns_connections = malloc(65536 * sizeof(sender_packet_map));
	
	while(1) {
		
		unsigned int rsize = recvfrom(fd, buf, 1024, 0, (struct sockaddr *)  sender, &len_sender);
		if (errno != 0) printf("Receiving error: %s\n", strerror(errno));
		
		u8 response = parse_dns(pkt, buf, rsize);
		if (response) {
			// search for transaction ID and forward response to initial sender
			u16 tmp_ti = get_u16(buf);
					
			if (dns_connections+tmp_ti) {
				forward_dns(fd, (dns_connections+tmp_ti), buf, rsize);
			}
			// free resources
			continue;
		}
		// check for ad
		// ...
		
		// forward DNS query
		send_query(fd, dns_connections, sender, len_sender, buf, rsize, &dns_server);		
	}
	
	close(fd);
	return 0;
}

void send_query(int fd, sender_packet_map * dns_connections, struct sockaddr_in * sender, u8 len_sender, char * buf, unsigned int rsize, struct sockaddr_in * dnsserver) {
	
	u16 trans_id = get_u16(buf);
	sender_packet_map * entry = malloc(sizeof(sender_packet_map));
	struct sockaddr_in * sender_info = malloc(len_sender);
	memcpy(sender_info, sender, len_sender);
	
	entry->ti = trans_id;
	entry->sender = sender_info;
	entry->len_sender = len_sender;
	
	dns_connections[trans_id] = *entry;
	
	unsigned int res = sendto(fd, buf, rsize, 0, (const struct sockaddr *) dnsserver, sizeof(*dnsserver));
	if (errno != 0) printf("Query sending error: %s\n", strerror(errno));
}

void forward_dns(int fd, sender_packet_map * mapping, char * data, u16 size) {
	int size = sendto(fd, data, size, 0, (const struct sockaddr *) mapping->sender, mapping->len_sender);
	if (errno != 0) printf("Forwarding sending error: %s\n", strerror(errno));
}

void get_dns_server(struct sockaddr_in * dns_server) {
	memset(dns_server, 0, sizeof(*dns_server));
	dns_server->sin_family = AF_INET;
	dns_server->sin_port = htons( DNS_PORT );
	dns_server->sin_addr.s_addr = inet_addr( GOOGLE_DNS );
}

int get_socket() {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	if (fd == -1) {
		printf("Error in opening socket.\n");
		return -1;
	}
	
	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int));
			   
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons( DNS_PORT );
	
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("Error in binding socket. %s\n", strerror(errno));
		return -1;
	}
	
	return fd;
}