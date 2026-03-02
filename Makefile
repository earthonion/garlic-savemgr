PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk

PS5_CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
PS5_INCDIR := $(PS5_PAYLOAD_SDK)/target/include
PS5_LIBDIR := $(PS5_PAYLOAD_SDK)/target/lib

CFLAGS := -O2 -Wall -D_BSD_SOURCE -std=gnu11 -Isrc -I$(PS5_INCDIR)
LDFLAGS := -L$(PS5_LIBDIR)
LIBS := -lkernel_sys -lkernel -lSceSystemService -lSceUserService -lSceFsInternalForVsh

all: garlic-savemgr.elf

src/ui.h: src/ui.html
	xxd -i $< > $@

garlic-savemgr.elf: src/main.c src/ui.h
	$(PS5_CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f garlic-savemgr.elf src/ui.h

.PHONY: all clean
