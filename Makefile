CFLAGS=-g
CC=g++

server: server.cpp
	${CC} ${CFLAGS} $^ -o $@ 

clean:
	rm -f server