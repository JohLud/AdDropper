#include <stdlib.h>
#include <string.h>

#include "addropper.h"

void get_type_and_class(char * data, u16 len, u16 * type, u16 * class) {
	// go back from end of packet to retrieve class and type
	*type = get_u16( data + (len-4) );
	*class = get_u16( data + (len-2) );
}

u16 build_zero_answer(char ** data, u16 len) {
	
	u16 resp_size = len + 16;
	
	char * new_data = malloc(resp_size);
	memcpy(new_data, *data, len);
	
	// *data = realloc(*data, len + 16);
	// char * new_data = *data;
	
	new_data[2] = 0x80;			// set first flag byte to 1000 0000 (for response)
	new_data[3] = 0x00;			// set second flag byte to 0
	new_data[7] = 0x01;			// contains an Anser RR
	
	// memcpy( new_data+12, new_data+len, (new_data+len) - (new_data+12));
	
	// u16 pkt_end = len;
	new_data[len] = 0xc0;	// set pointer
	new_data[len+1] = 0x0c;	// pointer to QNAME (offset in pkt = 13 byte)
	
	// get type and class
	u16 type;
	u16 class;
	get_type_and_class(*data, len, &type, &class);
	
	// set type and class
	new_data[len+2] = type >> 8;
	new_data[len+3] = type & 0xff;
	new_data[len+4] = class >> 8;
	new_data[len+5] = class & 0xff;
	
	// set TTL to 65535 seconds = 18 h
	new_data[len+6] = 0x00;
	new_data[len+7] = 0x00;
	new_data[len+8] = 0xff;
	new_data[len+9] = 0xff;
	
	// size of IPv4 address = 4 byte
	new_data[len+10] = 0x00;
	new_data[len+11] = 0x04;
	
	// IPv4 address = 0.0.0.0
	new_data[len+12] = 0x00;
	new_data[len+13] = 0x00;
	new_data[len+14] = 0x00;
	new_data[len+15] = 0x00;
	
	*data = new_data;
	
	return resp_size;
}
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