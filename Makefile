CFLAGS = -g -Wall -Werror

CFILES = shim.c 6relay.c tra6to4.c dhcp.c dhcpv4.c

all:	shim tra6to4

clean:
	rm -fr *.o tra6to4 6relay shim .depend

shim:	shim.o dhcp.o shim.h
	${CC} -o shim shim.o dhcp.o -lpcap

tra6to4: tra6to4.o dhcpv4.o shim.h
	${CC} -o tra6to4 tra6to4.o dhcpv4.o

6relay:	6relay.o dhcp.o shim.h
	${CC} -o 6relay 6relay.o dhcp.o
