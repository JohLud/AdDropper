#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "addropper.h"

int main(int arc, char ** argv) {
	int fd = get_socket();
	if (fd < 0) return 1;
	
	struct sockaddr_in sender;
	char * buf = malloc(MAX_DNS_SIZE);
	unsigned int len_sender = sizeof(sender);
	
	while(1) {

		unsigned int rsize = recvfrom(fd, buf, 1024, 0, (struct sockaddr *) &sender, &len_sender);
		if (errno != 0) printf("Error: %s\n", strerror(errno));
		
	}
	
	close(fd);
	return 0;
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