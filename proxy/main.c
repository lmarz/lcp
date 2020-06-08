#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT      4244
#define SLOT_NUM  10

struct proxy_link;
struct proxy_link {
	struct proxy_link *next;
	uint16_t id;
	char num;

	char                  mask[2];
	struct sockaddr_in6   addr[2];
};

struct proxy_table {
	struct proxy_link *links[SLOT_NUM];
};

int tbl_init(struct proxy_table *tbl);
void tbl_close(struct proxy_table *tbl);
struct proxy_link *tbl_get(struct proxy_table *tbl, uint16_t id);

extern int cli_send(int fd, struct sockaddr_in6 *addr, uint8_t op, uint16_t id);

int main(int argc, char **argv)
{
	int sockfd;
	struct sockaddr_in6 addr;
	struct sockaddr *addr_ptr = (struct sockaddr *)&addr;
	struct sockaddr_in6 from;
	struct sockaddr *from_ptr = (struct sockaddr *)&from;
	struct sockaddr_in6 to;
	struct sockaddr *to_ptr = (struct sockaddr *)&to;
	unsigned int size = sizeof(addr);
	int r;
	char buf[512];

	int i, idx;
	uint8_t op;
	uint16_t id;
	struct proxy_link *ptr;
	struct proxy_link *lnk;
	struct proxy_table tbl;

	/* Initialize the proxy-table */
	if(tbl_init(&tbl) < 0)
		return -1;

	if((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
		return -1;

	memset(&addr, 0, size);
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(PORT);
	addr.sin6_addr = in6addr_any;

	if(bind(sockfd, addr_ptr, size) < 0) 
		goto err_close_sockfd;

	while(1) {
		if((r = recvfrom(sockfd, buf, 512, 0, from_ptr, &size)) > 0) {
			/* Handle ping */
			if(*(short *)buf == 0x00) {
				buf[0] = 0;
				buf[1] = 1;
				sendto(sockfd, buf, 2, 0, from_ptr, size);
			}

			printf("Code: %02x\n", (unsigned char)buf[0]);

			/*
			 * Validate packet-header and identify packet as
			 * request.
			 */
			if((unsigned char)buf[0] != 0xff)
				continue;

			op = buf[1];
			memcpy(&id, buf + 2, 2);

			printf("Received %d bytes, OP: %d, Id: %d\n", r, op, id);

			/*
			 * Join a link, or create a new one if necessary.
			 */
			if(op == 0x01) {
				/*
				 * Check if a link with that id already exists.
				 */
				lnk = tbl_get(&tbl, id);

				/*
				 * If the link doesn't yet exist.
				 */
				if(!lnk) {
					if(!(lnk = malloc(sizeof(struct proxy_link)))) {
						cli_send(sockfd, &from, 0x06, id);
						goto next;
					}

					lnk->next = NULL;
					lnk->id = id;
					lnk->num = 1;
					lnk->mask[0] = 1;
					lnk->mask[1] = 0;
					lnk->addr[0] = from;

					if(!(ptr = tbl.links[id % SLOT_NUM])) {
						tbl.links[id % SLOT_NUM] = lnk;
						cli_send(sockfd, &from, 0x05, id);
						goto next;
					}

					while(ptr->next != NULL)
						ptr = ptr->next;

					ptr->next = lnk;
					cli_send(sockfd, &from, 0x05, id);
					goto next;
				}
				else {
					/* 
					 * Check if the address is
					 * already linked.
					 */
					for(i = 0; i < 2; i++) {
						if(lnk->mask[i] != 0) {
							if(memcmp(&lnk->addr[i], &from, size) == 0) {
								cli_send(sockfd, &from, 0x06, id);
								goto next;
							}
						}
					}

					for(i = 0; i < 2; i++) {
						if(lnk->mask[i] == 0) {
							lnk->num++;
							lnk->mask[i] = 1;
							lnk->addr[i] = from;
							cli_send(sockfd, &from, 0x05, id);

							if(lnk->num == 2) {
								printf("Linking complete\n");
								for(i = 0; i < 2; i++)
									cli_send(sockfd, &lnk->addr[i], 0x04, id);

							}

							goto next;
						}
					}

					cli_send(sockfd, &from, 0x06, id);
				}
			}
			/*
			 * Leave a link and delete if empty.
			 */
			else if(buf[1] == 0x02 && !(lnk = tbl_get(&tbl, id))) {
				printf("Leave\n");

				for(i = 0; i < 2; i++) {
					if(memcmp(&lnk->addr[i], &from, size) == 0) {
						lnk->num--;
						lnk->mask[i] = 0;
						break;
					}
				}
				cli_send(sockfd, &from, 0x05, id);
				goto next;
			}
			/* 
			 * Relay packet using link.
			 */
			else if(buf[1] == 0x03) {
				printf("Relay\n");

				idx = -1;
				for(i = 0; i < 2; i++) {
					if(memcmp(&lnk->addr[i], &from, size) == 0) {
						idx = i;
						break;
					}
				}

				if(idx == -1)
					goto next;

				if(lnk->mask[(idx + 1) % 2] == 0)
					goto next;

				printf("Relay message\n");
				to_ptr = (struct sockaddr *)&lnk->addr[(idx + 1) % 2];
				sendto(sockfd, buf, r, 0, to_ptr, size);
				goto next;
			}

next:
			if(1){}
			/* Just await the next message */
		}
	}

err_close_sockfd:
	close(sockfd);
	return 0;
}

int tbl_init(struct proxy_table *tbl)
{
	int i;

	for(i = 0; i < SLOT_NUM; i++)
		tbl->links[i] = NULL;

	return 0;
}


void tbl_close(struct proxy_table *tbl)
{
	int i;

	for(i = 0; i < SLOT_NUM; i++) {
		if(tbl->links[i] != NULL) {

		}
	}
}


struct proxy_link *tbl_get(struct proxy_table *tbl, uint16_t id)
{
	struct proxy_link *ptr;

	if(!(ptr = tbl->links[id % SLOT_NUM]))
		return NULL;

	while(ptr != NULL) {
		if(ptr->id == id)
			return ptr;

		ptr = ptr->next;
	}

	return NULL;
}


int cli_send(int fd, struct sockaddr_in6 *addr, uint8_t op, uint16_t id)
{
	char buf[4];
	struct sockaddr *dst = (struct sockaddr *)addr;
	int tmp = sizeof(struct sockaddr_in6);

	buf[0] = 0xff;
	buf[1] = op;
	memcpy(buf + 2, &id, 2);

	return sendto(fd, buf, 4, 0, dst, tmp);
}
