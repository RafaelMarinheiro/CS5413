all: tcp-proxy

CFLAGS = -Wall -g -O2 
LFLAGS = -pthread
CC = gcc 
PS2PDF = ps2pdf14
DIST_FILE = tcp-proxy.tar.gz

tcp-proxy: tcp-proxy.c acceptor.o bridge.o
	$(CC) $(LFLAGS) -o $@ $^

bridge.o: Bridge.c Acceptor.h Bridge.h
	$(CC) $(LFLAGS) -c -o $@ $<

acceptor.o: Acceptor.c Acceptor.h Bridge.h
	$(CC) $(LFLAGS) -c -o $@ $<

dist: clean
	tar -czf $(DIST_FILE) ../tcp-proxy-single-thread --exclude="*.tar.gz"

clean:
	rm -fr .DS_Store *.tar.gz *.ps *.pdf *.o *.dSYM *~ tcp-proxy test-tcpproxy
