#include <stdint.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "addropper.h"
	
u8 get_u8(char * data) {
	return *((u8 *) data);
}

u16 get_u16(char * data) {
	return htons( *((u16 *) data) );
}

u32 get_u32(char * data) {
	return htonl( *((u32 *) data) );
}

u64 get_u64(char * data) {
	// htonll is not defined?
	u64 d1 = get_u32(data);
	u32 d2 = get_u32(data+4);
	u64 erg = d1 << 32;
	erg += d2;
	return erg;
}