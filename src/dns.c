#include <stdlib.h>

#include "addropper.h"

void parse_dns_rr(dns_packet * pkt, char * data, u16 pos, u16 len) {
	
	u8 maxlenofdomain = len - pos - 4;
	char * domain = malloc(maxlenofdomain);
	
	u16 domain_index = 0;
	u8 reading = get_u8(data + pos);
	pos++;
	
	while(reading) {
		for (int i = 0; i < reading; i++) {
			domain[ domain_index ] = *(data+pos+i);
			domain_index++;
		}
		pos += reading;
		domain [ domain_index ] = '.';
		domain_index++;
		reading = get_u8(data + pos);
		pos++;
	}
	
	// to remove last '.'
	domain[domain_index - 1] = '\0';
	
	pkt->domain = domain;
}

void parse_dns_flags(u16 flags, dns_packet * pkt) {
	u8 qr = flags >> 15 & 0x1;
	pkt->qr = qr;
	u8 opcode = flags >> 11 & 0xF;
	pkt->opcode = opcode;
	u8 aatcrdra = flags >> 7 & 0xF;
	pkt->aatcrdra = aatcrdra;
	u8 rcode = flags & 0xF;
	pkt->rcode = rcode;
}

/**
* Parses an incomming DNS packet.
* Returns 1 if it is a response and 0 otherwise.
*/
u8 parse_dns(dns_packet * pkt, char * data, u16 len) {

	u16 pos = 0;
	u16 id = get_u16(data);
	pkt->id = id;
	pos += 2;
	u16 flags = get_u16(data+pos);
	pos += 2;
	
	// parse flags and return 1 if it is a response.
	parse_dns_flags(flags, pkt);
	if (pkt->qr) return 1;
	
	u16 qdcount = get_u16(data+pos);
	pkt->qdcount = qdcount;
	pos += 2;
	u16 ancount = get_u16(data+pos);
	pkt->ancount = ancount;
	pos += 2;
	u16 nscount = get_u16(data+pos);
	pkt->nscount = nscount;
	pos += 2;
	u16 arcount = get_u16(data+pos);
	pkt->arcount = arcount;
	pos += 2;
	
	parse_dns_rr(pkt, data, pos, len);
	
	return 0;
}