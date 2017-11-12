all: clean pbproxy 

pbproxy: pbproxy.c
	gcc -o pbproxy pbproxy.c -L/usr/lib -lssl -lcrypto -lpthread

clean:
	rm -f pbproxy 

