CFLAGS=-g -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -std=c++11
CC=g++
OPTIMIZE=-O3

server: server.cpp
	${CC} ${CFLAGS} ${OPTIMIZE} $^ -o $@ 

clean:
	rm -f server
