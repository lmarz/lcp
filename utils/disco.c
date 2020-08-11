#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 4243

int main(void)
{
	int sockfd;
	struct sockaddr_in6 serv;
	struct sockaddr *serv_ptr = (struct sockaddr *)&serv;
	struct sockaddr_in6 cli;
	struct sockaddr *cli_ptr = (struct sockaddr *)&cli;
	int s_sz = sizeof(struct sockaddr_in6);
	char buf[512];
	int r;

	if((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0) {
		perror("socket()");
		return -1;
	}

	memset(&serv, 0, s_sz);
	serv.sin6_family = AF_INET6;
	serv.sin6_port = htons(PORT);
	serv.sin6_addr = in6addr_any;
	if(bind(sockfd, serv_ptr, s_sz) < 0) {
		perror("bind()");
		goto err_close_sockfd;
	}

	while(1) {
		if((r = recvfrom(sockfd, buf, 512, 0, cli_ptr, &s_sz)) > 0) {
			if(sendto(sockfd, &cli, s_sz, 0, cli_ptr, s_sz) < 0) {
				perror("send()");
				goto err_close_sockfd;
			}
		}
	}

err_close_sockfd:
	close(sockfd);
	return 0;
}

