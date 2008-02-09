CC=gcc
CFLAGS=-Wall -Wno-parentheses -g -D_REENTRANT

all: autoddns

OBJS=watchip.o autoddns.o iplist.o dnsquery.o dnsupdate.o

autoddns: $(OBJS)
	$(CC) -o $@ $(OBJS) -lpthread -lresolv

autoddns.o: autoddns.c watchip.h iplist.h dnsquery.h dnsupdate.h

watchip.o: watchip.c watchip.h iplist.h

iplist.o: iplist.c iplist.h

dnsquery.o: dnsquery.c dnsquery.h

dnsupdate.o: dnsupdate.c dnsquery.h iplist.h

clean:
	rm -rf $(OBJS) autoddns
