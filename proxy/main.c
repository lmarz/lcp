#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	short port;
	int sockfd;
	struct sockaddr_in6 addr;
	struct sockaddr *addr_ptr = (struct sockaddr *)&addr;
	struct sockaddr_in6 from;
	struct sockaddr *from_ptr = (struct sockaddr *)&from;
	struct sockaddr_in6 to;
	struct sockaddr *to_ptr = (struct sockaddr *)&to;
	int size = sizeof(addr);
	int r;
	char buf[512];

	if(argc < 2) {
		printf("usage: %s <port>\n", argv[0]);
		return -1;
	}

	port = atoi(argv[1]);

	if((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
		return -1;

	memset(&addr, 0, size);
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;

	if(bind(sockfd, addr_ptr, size) < 0) 
		goto err_close_sockfd;

	while(1) {
		if((r = recvfrom(sockfd, buf, 512, 0, from_ptr, &size)) > 0) {
			if(r < 24) continue;

			if(*(short *)buf == 0x00) {
				buf[0] = 0;
				buf[1] = 1;
				sendto(sockfd, buf, 2, 0, from_ptr, size);
			}


			/* Set the address to relay packet to */
			memset(&to, 0, size);
			to.sin6_family = AF_INET6;
			port = *(short *)(buf + 2);
			to.sin6_port = port;
			memcpy(&to.sin6_addr, buf + 4, 16);

			/* Update packet header */
			*(short *)buf = 0xbeef;
			memcpy(buf + 2, &from.sin6_port, 2);
			memcpy(buf + 4, &from.sin6_addr, 16);

			/* Send packet */
			sendto(sockfd, buf, r, 0, to_ptr, size);
		}
	}
		
err_close_sockfd:
	close(sockfd);
	return 0;
}
