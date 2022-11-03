#Makefile for twrmon

.PHONY: all clean docker dockerarm

### バージョンの定義
VERSION     := "v1.0.0"
COMMIT      := $(shell git rev-parse --short HEAD)
WD          := $(shell pwd)
DIST = dist
TWRMOND_OBJS=twrmond.o rmon.o rmonTable.o
TWRMOND_H=twrmond.h rmon.h  rmonTable.h
TWRMOND_C=twrmond.c rmon.c  rmonTable.c

SNMP_CF = -W -O2 -I. `net-snmp-config --cflags`
SNMP_AGENT_LIBS=`net-snmp-config --agent-libs`
PCAP_LIB =  -lpcap

all:  $(DIST)/twrmond

#Agentx for RMON MIB
twrmond.o: twrmond.c $(TWRMOND_H)
	gcc $(SNMP_CF) -c $*.c

rmon.o: rmon.c $(TWRMOND_H)
	gcc $(SNMP_CF) -c $*.c

rmonTable.o: rmonTable.c $(TWRMOND_H)
	gcc $(SNMP_CF) -c $*.c

$(DIST)/twrmond: $(TWRMOND_OBJS)
	gcc -o dist/twrmond $(TWRMOND_OBJS)  $(SNMP_AGENT_LIBS) $(PCAP_LIB)

docker:  $(DIST)/twrmon Docker/Dockerfile
	cp dist/twrmon Docker/
	cd Docker && docker build -t twsnmp/twrmon .

dockerarm: Docker/Dockerfile dist/twrmon.arm dist/twrmon.arm64
	cp dist/twrmon.arm Docker/twrmon
	cd Docker && docker buildx build --platform linux/arm/v7 -t twsnmp/twrmon:armv7_$(VERSION) --push .
	cp dist/twrmon.arm64 Docker/twrmon
	cd Docker && docker buildx build --platform linux/arm64 -t twsnmp/twrmon:arm64_$(VERSION) --push .

$(DIST)/twrmon.arm: $(TWRMOND_C) $(TWRMOND_H)
	docker run --rm -v "$(WD)":/twrmon -w /twrmon debian:bullseye-slim /twrmon/mkarm.sh $(DIST) $(VERSION) $(COMMIT)
$(DIST)/twrmon.arm64: $(TWRMOND_C) $(TWRMOND_H)
	docker run --rm -v "$(WD)":/twrmon -w /twrmon debian:bullseye-slim /twrmon/mkarm64.sh $(DIST) $(VERSION) $(COMMIT)

clean:
	rm -f *.o dist/twrmond
	mkdir -p dist
