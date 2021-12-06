#ifndef ADDROPPER_HEADER
#define ADDROPPER_HEADER

#define DNS_PORT 53
#define MAX_DNS_SIZE 1024

#define GOOGLE_DNS "8.8.8.8"


#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef struct q_resource_record {
	char * name;			// owner of the query (domain name)
	u16 type;				// type of query
	u16 class;				// class of query e.g. IN (Internet)
} q_resource_record;

typedef struct dns_packet {
	u16 id;				// id of the query
	u8 qr;				// 1 Bit: query (0) or response (1)
	u8 opcode;			// 4 Bit: kind of query
	u8 aatcrdra;		// the other flags AA TC RD RA
	u8 rcode;			// response code
	u16 qdcount;		// number of entries in question section
	q_resource_record * q_rr;	// pointer to the QRR
	u16 ancount;		// number of entries in answer section
	u16 nscount;		// number of entries in authority section
	u16 arcount;		// number of entries in additional records section
} dns_packet;

typedef struct sender_packet_map {
	u16 ti;			// transaction id
	struct sockaddr_in * sender;
	u16 len_sender;
} sender_packet_map;

/*
	MEMHELPER
*/
u8 get_u8(char * data);
u16 get_u16(char * data);
u32 get_u32(char * data);
u64 get_u64(char * data);
		
/*
	DNS PARSER
*/
void parse_dns_flags(u16 flags, dns_packet * pkt);
u8 parse_dns(dns_packet * pkt, char * data, u16 len);

/*
	MAIN
*/
int get_socket();
void send_query(int fd, u64 * dns_connections, struct sockaddr_in * sender, char * buf, unsigned int rsize, struct sockaddr_in * dnsserver);
void forward_dns(int fd, sender_packet_map * mapping, char * data, u16 size);
void get_dns_server(struct sockaddr_in * dns_server);
#endif // ADDROPPER_HEADER