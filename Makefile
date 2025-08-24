CFLAGS=-g -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
CC=g++
OPTIMIZE=-O3

server: server.cpp
	${CC} ${CFLAGS} ${OPTIMIZE} $^ -o $@ 

clean:
	rm -f server
