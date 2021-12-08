#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "addropper.h"

_Bool check_in_file(char * domain, u16 domain_len) {
	FILE* fd;
	fd = fopen("banlists/AdAway.txt", "r");
	
	char tmp_domain[256];
	while(fgets(tmp_domain, 256, fd) != NULL) {
		
		u16 len_tmp_domain = strlen(tmp_domain) - 1;
		u16 smallest_len = domain_len <= len_tmp_domain ? domain_len : len_tmp_domain;

		if (strncmp(domain, tmp_domain, smallest_len) == 0) return 1;
	}
	return 0;
}

char * cut_www(char * domain) {
	u16 len = strlen(domain);
	_Bool www = 0;
	if (strncmp(domain, "w", 1) == 0) {
		char * newdom = malloc(len - 4);
		for (int i = 0; i < len - 4; i++) {
			newdom[i] = domain[i+4];
		}
		free(domain);
		return newdom;
	}
	return domain;
}

_Bool check_ad_domain(char ** domain) {
	
	*domain = cut_www(*domain);
	u16 domlen = strlen(*domain);
	
	// for banlist file in banlists/
	if (check_in_file(*domain, domlen)) return 1;
	return 0;
}