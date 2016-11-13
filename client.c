// Fredrik Berglund 2016

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#define PROTOSIZE 8
#define MAXDATASIZE 125004 // max number of bytes we can get at once
#define DEBUG 0

struct protocol_message {
    uint8_t op;
    uint8_t proto;
    uint16_t checksum;
    uint32_t trans_id;
};

struct proto2_m {
    uint32_t length;
    char string[MAXDATASIZE-4];
};

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// https://stackoverflow.com/questions/8845178/c-programming-tcp-checksum
uint16_t calc_checksum(uint16_t *buffer, int size)
{
    uint32_t cksum = 0;
    while(size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(uint16_t);
    }
    if(size)
        cksum += *(unsigned char*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (uint16_t)(~cksum);
}

void hton_protocol_message(struct protocol_message p_m, char buffer[8]) {
    uint16_t u16;
    uint32_t u32;

    memcpy(buffer+0, &p_m.op, 1);

    memcpy(buffer+1, &p_m.proto, 1);

    u32 = htonl(p_m.trans_id);
    memcpy(buffer+4, &u32, 4);

    u16 = htons(calc_checksum((uint16_t*)buffer, 8));
    memcpy(buffer+2, &u16, 2);
}

void ntoh_protocol_message(struct protocol_message *p_m, char buffer[8]) {
    uint16_t u16;
    uint32_t u32;

    p_m->op = buffer[0];

    p_m->proto = buffer[1];

    memcpy(&u16, buffer+2, 2);
    p_m->checksum = ntohs(u16);

    memcpy(&u32, buffer+4, 4);
    p_m->trans_id = ntohl(u32);
}

void check_protocol_message(struct protocol_message *p_m, char p_buf[8]) {
    char check_buf[8];

    ntoh_protocol_message(p_m, p_buf);

    if(DEBUG) {
        printf("\np_m.op %u\n", p_m->op);
        printf("p_m->proto %u\n", p_m->proto);
        printf("p_m->checksum %u\n", p_m->checksum);
        printf("p_m->trans_id %u\n", p_m->trans_id);
    }

    // Check checksum
    memcpy(check_buf, p_buf, 8);
    check_buf[2] = 0;
    check_buf[3] = 0;
    uint16_t check = calc_checksum((uint16_t*)check_buf, 8);
    if(check != p_m->checksum) {
        perror("error: bad checksum");
        exit(EXIT_FAILURE);
    }
    if(DEBUG) {
        puts("Checksum OK!\n");
    }

    // Check the op
    if(p_m->op != 1) {
        perror("error: bad op");
        exit(EXIT_FAILURE);
    }

    // Check the protocol
    if(p_m->proto != 1 && p_m->proto != 2) {
        perror("error: bad protocol");
        exit(EXIT_FAILURE);
    }
}

void hton_proto2_m(struct proto2_m p_m, char buffer[MAXDATASIZE]) {
    uint32_t u32;

    u32 = htonl(p_m.length);
    memcpy(buffer+0, &u32, 4);

    memcpy(buffer+4, p_m.string, p_m.length);
}

void send_proto_1(int socket_fd, char str[MAXDATASIZE-2]) {
    int numbytes;
    size_t total = 0;
    size_t len = strlen(str)+1;
    char terminator[2] = "\\0";

    if(len < MAXDATASIZE-4) {
        memcpy(str+len-2, terminator, 2);
    } else {
        memcpy(str+MAXDATASIZE-4, terminator, 2);
    }

    while (total != len) {
        if ((numbytes = send(socket_fd, str + total, len - total, 0)) == -1) {
            perror("error: send message");
        }
        total += numbytes;
    }

    if (shutdown(socket_fd, SHUT_WR) == -1 ) {
        perror("socket shutdown failed");
    }

    if(DEBUG) {
        printf("client: sent '%s'\n", str);
    }
}

void send_proto_2(int socket_fd, char data[MAXDATASIZE], struct proto2_m p2_m) {
    int numbytes;
    size_t total = 0;
    size_t len = p2_m.length + 4;

    while (total != len) {
        if ((numbytes = send(socket_fd, data + total, len - total, 0)) == -1) {
            perror("error: send message");
        }
        total += numbytes;
    }

    if (shutdown(socket_fd, SHUT_WR) == -1 ) {
        perror("socket shutdown failed");
    }

    if(DEBUG) {
        printf("client: sent '%s'\n", data);
    }
}

int main(int argc , const char *argv[]) {
    struct addrinfo hints, *res, *p;
    int status, socket_fd, numbytes;
    char buf[MAXDATASIZE];
    char s[INET6_ADDRSTRLEN];
    unsigned short proto;
    char p_buf[8];
    struct protocol_message p_m;
    size_t total;
    struct proto2_m p2_m;

    srand(time(NULL));

    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_UNSPEC; // AF_INET for IPv4
    hints.ai_socktype = SOCK_STREAM;

    if(argc == 7) {
        if(strcmp(argv[1], "-h") == 0 &&
            strcmp(argv[3], "-p") == 0 &&
            strcmp(argv[5], "-m") == 0) {

            // protocol number (0/1/2)
            if(strcmp(argv[6],"0") == 0 ||
                strcmp(argv[6],"1") == 0 ||
                strcmp(argv[6],"2") == 0) {
                proto = (unsigned short)strtoul(&argv[6][0], NULL, 0);
            } else {
                fprintf(stderr, "protcol: '%s' not valid.", argv[6]);
                exit(EXIT_FAILURE);
            }

            if((status = getaddrinfo(argv[2], argv[4], &hints, &res)) != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
                exit(EXIT_FAILURE);
            }

        } else {
            printf("Arguments:\n%s %s %s\n", argv[1], argv[3], argv[5]);
            printf("%s:%s %s\n", argv[2], argv[4], argv[6]);
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "usage: %s –h xxx.xxx.xxx.xxx –p xxxx –m 0/1/2\n
        	Where -h is host address, -p is port# and -m is protocol.\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Loop through all the results and connect to the first we can
    for(p = res; p != NULL; p = p->ai_next) {
        // IPv, TCP/UDP, IP proto #
        if((socket_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: could not create socket");
            continue;
        }

        if(connect(socket_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(socket_fd);
            perror("client: failed to connect");
            continue;
        }

        break;
    }

    if(p == NULL) {
        perror("client: failed to connect");
        exit(EXIT_FAILURE);
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(res); // free the linked list

    /*
    * NEGOTIATE ABOUT PROTOCOL
    */
    p_m.op = 0;
    p_m.proto = proto;
    p_m.trans_id = rand() % 8998 + 1001;

    hton_protocol_message(p_m, p_buf);

    if (send(socket_fd, p_buf, PROTOSIZE, 0) == -1) {
        perror("error: send protocol message");
    }
    if(DEBUG) {
        puts("client: sent protocol request");
    }

    // RECIEVE PROTOCOL
    memset(&p_buf[0], 0, sizeof(p_buf));
    total = 0;
    while(1) {
        if((numbytes = recv(socket_fd, p_buf + total, PROTOSIZE, 0)) == -1) {
            perror("error: recv protocol");
            exit(EXIT_FAILURE);
        }

        if(numbytes != 0) {
            if(DEBUG) {
                printf("client: recieved %i bytes.\n", numbytes);
            }
            total += numbytes;
            if(total == PROTOSIZE) {
                break;
            }
        } else {
            break;
        }
    }

    if(DEBUG) {
        printf("client: recieved %i bytes.\n", numbytes);
    }

    check_protocol_message(&p_m, p_buf);

    /*
    * Get message input
    */
    char *m_buf;
    size_t m_bufsize = MAXDATASIZE-4;
    m_buf = (char *)malloc(m_bufsize * sizeof(char));
    if( m_buf == NULL)
    {
        perror("Unable to allocate m_buf");
        exit(1);
    }

    printf("Enter a message: ");
    total = 0;
    while (fgets(m_buf + total, sizeof m_buf, stdin) != NULL) {
        total = strlen(m_buf);
        if(DEBUG) {
            printf("total: %zu\n", total);
        }
    }

    /*
    * SEND MESSAGE
    */
    if(p_m.proto == 1) {
        send_proto_1(socket_fd, m_buf);
    } else {
        p2_m.length = strlen(m_buf)-1;
        strcpy(p2_m.string, m_buf);
        hton_proto2_m(p2_m, buf);
        send_proto_2(socket_fd, buf, p2_m);
    }

    // receive message
    memset(&buf[0], 0, sizeof(buf));
    total = 0;
    while(1) {
        if((numbytes = recv(socket_fd, buf + total, MAXDATASIZE-1, 0)) == -1) {
            perror("error: recv protocol");
            exit(EXIT_FAILURE);
        }

        if(numbytes != 0) {
            total += numbytes;
            if(DEBUG) {
                printf("client: recieved %i bytes.\n", numbytes);
            }
        } else {
            break;
        }
    }

    printf("client: recieved:\n%s\n", buf);

    close(socket_fd);

    return 0;
}
