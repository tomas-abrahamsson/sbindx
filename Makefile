sysname := $(shell uname -s)

libs_FreeBSD =
libs_Linux = -lsctp
libs_SunOS = -lsocket -lnsl -lsctp

all:	sbindx

sbindx: sbindx.c
	gcc -Wall -g -o $@ $<

clean:
	$(RM) sbindx
