CC    = gcc

FLAGS = -std=gnu99 -pedantic -W -Wall

all: server client

server: server.c
	$(CC) $(FLAGS) -o server server.c

client: client.c
	$(CC) $(FLAGS) -o client client.c
