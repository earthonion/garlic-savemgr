PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
VERSION ?= 1.8b

PS5_CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
PS5_INCDIR := $(PS5_PAYLOAD_SDK)/target/include
PS5_LIBDIR := $(PS5_PAYLOAD_SDK)/target/lib

CFLAGS := -O2 -Wall -D_BSD_SOURCE -std=gnu11 -Isrc -I$(PS5_INCDIR)
SQLITE_FLAGS := -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_WAL -w
LDFLAGS := -L$(PS5_LIBDIR)
LIBS := -lkernel_sys -lkernel -lSceSystemService -lSceUserService -lSceFsInternalForVsh -lSceRegMgr

all: garlic-savemgr.elf

src/ui.h: src/ui.html
	sed 's/__VERSION__/v$(VERSION)/g' $< > src/_ui_tmp.html
	xxd -i src/_ui_tmp.html > $@
	sed -i 's/src__ui_tmp_html/src_ui_html/g' $@
	rm -f src/_ui_tmp.html

src/sqlite3.o: src/sqlite3.c
	$(PS5_CC) -O2 -D_BSD_SOURCE -std=gnu11 -I$(PS5_INCDIR) $(SQLITE_FLAGS) -c -o $@ $<

garlic-savemgr.elf: src/main.c src/ui.h src/sqlite3.o
	$(PS5_CC) $(CFLAGS) $(LDFLAGS) -o $@ src/main.c src/sqlite3.o $(LIBS)

clean:
	rm -f garlic-savemgr.elf src/ui.h src/sqlite3.o src/_ui_tmp.html

.PHONY: all clean
