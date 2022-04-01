all :	schat.o
	$(CC) $(CFLAGS) -o schat schat.o $(CLIBS)

CC = gcc
CFLAGS = 
CLIBS = -lssl -lcrypto

schat.o :	schat.c
	$(CC) $(CFLAGS) -c schat.c

clean :
	rm schat.o

install :
	mv schat /usr/local/bin

