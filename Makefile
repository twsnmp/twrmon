#Makefile for twrmon

.PHONY: all clean

### バージョンの定義
VERSION     := "v1.0.1"
COMMIT      := $(shell git rev-parse --short HEAD)
WD          := $(shell pwd)
TWRMOND_OBJS=twrmond.o rmon.o rmonTable.o
TWRMOND_H=twrmond.h rmon.h  rmonTable.h
TWRMOND_C=twrmond.c rmon.c  rmonTable.c

SNMP_CF = -W -O2 -I. `net-snmp-config --cflags`
SNMP_AGENT_LIBS = `net-snmp-config --agent-libs`
PCAP_LIB = -lpcap -pthread
CC ?= gcc

all:  twrmond

#Agentx for RMON MIB
twrmond.o: twrmond.c $(TWRMOND_H)
	$(CC) $(SNMP_CF) -D 'VERSION=$(VERSION)' -D 'GITCOMMIT="$(COMMIT)"' -c $*.c

rmon.o: rmon.c $(TWRMOND_H)
	$(CC) $(SNMP_CF) -c $*.c

rmonTable.o: rmonTable.c $(TWRMOND_H)
	$(CC) $(SNMP_CF) -c $*.c

twrmond: $(TWRMOND_OBJS)
	$(CC) -o twrmond $(TWRMOND_OBJS)  $(SNMP_AGENT_LIBS) $(PCAP_LIB)

clean:
	rm -f *.o twrmond
