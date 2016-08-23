// Fredrik Berglund 2016

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>

#define BACKLOG 10     // how many pending connections queue will hold

#define PROTOSIZE 8
#define MAXDATASIZE 125004 // max number of bytes we can get at once
#define DEBUG 0

struct protocol_message {
    uint8_t op;
    uint8_t proto;
    uint16_t checksum;
    uint32_t trans_id;
};

void sigchld_handler()
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

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
    // char buf2[4];
    uint16_t u16;
    uint32_t u32;

    p_m->op = buffer[0];

    p_m->proto = buffer[1];

    memcpy(&u16, buffer+2, 2);
    p_m->checksum = ntohs(u16);

    memcpy(&u32, buffer+4, 4);
    p_m->trans_id = ntohl(u32);
}

// Returns the protocol to use
void check_protocol_message(struct protocol_message *p_m, char p_buf[8]) {
    char check_buf[8];

    ntoh_protocol_message(p_m, p_buf);

    if(DEBUG) {
        printf("\np_m->op %u\n", p_m->op);
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
    if(p_m->op != 0) {
        perror("error: bad op");
        exit(EXIT_FAILURE);
    }

    // Check the protocol
    if(p_m->proto == 0) {
        p_m->proto = rand() % 1 + 1;
    } else if(p_m->proto != 1 && p_m->proto != 2) {
        perror("error: bad protocol");
        exit(EXIT_FAILURE);
    }
}

void recieve_proto_1(int new_fd, char buf[MAXDATASIZE]) {
    int numbytes;
    size_t total = 0;
    char temp_buf[MAXDATASIZE];

    while(1) {
        if((numbytes = recv(new_fd, temp_buf + total, MAXDATASIZE-2, 0)) == -1) {
            perror("error: recv protocol");
            exit(EXIT_FAILURE);
        }

        if(numbytes != 0) {
            if(DEBUG) {
                printf("server: recieved %i bytes.\n", numbytes);
            }

            for(size_t i = total; i < (total+numbytes-1); ++i) {
                if( (temp_buf[i] == '\\' && temp_buf[i+1] == '0') ) {
                    if(i != 0 && temp_buf[i-1] == '\\' && i != (total+numbytes-2)) {
                        // Do nothing
                    } else {
                        memcpy(buf+0, temp_buf+0, total+i);
                        break;
                    }
                }
            }
            total += numbytes;

        } else { // End of stream
            break;
        }
    }
    if(DEBUG) {
        printf("server: received '%s'\n",buf);
    }
}

void recieve_proto_2(int new_fd, char buf[MAXDATASIZE-4]) {
    int numbytes;
    size_t total = 0;
    uint32_t u32;
    uint32_t len;
    char len_buffer[4];

    // Get string length
    while(1) {
        if((numbytes = recv(new_fd, len_buffer + total, 4, 0)) == -1) {
            perror("error: recv protocol");
            exit(EXIT_FAILURE);
        }

        if(DEBUG) {
            printf("server: recieved %i bytes.\n", numbytes);
            printf("server: recieved %u %u %u %u.\n", len_buffer[0],
                len_buffer[1], len_buffer[2], len_buffer[3]);
        }

        total += numbytes;

        if(total == 4) {
            memcpy(&u32, len_buffer, 4);
            len = ntohl(u32);
            break;
        }
    }

    total = 0;
    while(1) {
        if((numbytes = recv(new_fd, buf + total, len, 0)) == -1) {
            perror("error: recv protocol");
            exit(EXIT_FAILURE);
        }

        if(numbytes != 0) {
            total += numbytes;
            if(DEBUG) {
                printf("server: recieved %i bytes.\n", numbytes);
            }
        } else { // End of stream
            break;
        }
    }

    if(DEBUG) {
        printf("server: received '%s'\n",buf);
    }
}

void remove_redundancy(char buf[MAXDATASIZE]) {
    size_t i = 0, j = 0;
    while(i < strlen(buf)) {
        if(buf[i] == buf[i+1]) {
            ++i;
        } else {
            buf[j] = buf[i];
            ++i;
            ++j;
        }
    }
    buf[j] = '\0';
}

int main(int argc, const char *argv[]) {
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    char port[4];

    int numbytes;
    char buf[MAXDATASIZE];
    char p_buf[8];
    struct protocol_message p_m;

    srand(time(NULL));

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if(argc == 3 && strcmp(argv[1], "-p") == 0) {
        strcpy(port, argv[2]);
    } else {
        fprintf(stderr, "usage: %s –p xxxx\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("server: setsockopt");
            exit(EXIT_FAILURE);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if(!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener

            // Receive protocol request
            size_t total = 0;
            while(1) {
                if((numbytes = recv(new_fd, p_buf + total, PROTOSIZE, 0)) == -1) {
                    perror("error: recv protocol");
                    exit(EXIT_FAILURE);
                }

                if(numbytes != 0) {
                    if(DEBUG) {
                        printf("server: recieved %i bytes.\n", numbytes);
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
                printf("server: received protocol request %u %u %u %u ",
                    p_buf[0], p_buf[1], p_buf[2], p_buf[3]);
                printf("%u %u %u %u\n", p_buf[4], p_buf[5], p_buf[6], p_buf[7]);
            }

            check_protocol_message(&p_m, p_buf);

            // Put together a response
            p_m.op = 1;

            memset(&p_buf, 0, sizeof p_buf);

            hton_protocol_message(p_m, p_buf);
            if(DEBUG) {
                printf("server: sending protocol response %u %u %u %u ",
                    p_buf[0], p_buf[1], p_buf[2], p_buf[3]);
                printf("%u %u %u %u\n", p_buf[4], p_buf[5], p_buf[6], p_buf[7]);
            }

            if (send(new_fd, p_buf, PROTOSIZE, 0) == -1) {
                perror("error: send protocol response");
            }

            printf("server: waiting for message...\n");
            if(p_m.proto == 1) {
                recieve_proto_1(new_fd, buf);
            } else {
                recieve_proto_2(new_fd, buf);
            }

            remove_redundancy(buf);

            /*
            * Send redundancy removed string back
            */
            if (send(new_fd, buf, strlen(buf), 0) == -1)
                perror("error: send");

            printf("server: sent:\n%s\n", buf);

            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }

    return 0;
}
