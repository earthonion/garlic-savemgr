PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
VERSION ?= 1.14

PS5_CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
PS5_INCDIR := $(PS5_PAYLOAD_SDK)/target/include
PS5_LIBDIR := $(PS5_PAYLOAD_SDK)/target/lib

CFLAGS := -O2 -Wall -D_BSD_SOURCE -std=gnu11 -Isrc -I$(PS5_INCDIR)
SQLITE_FLAGS := -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_WAL -w
LDFLAGS := -L$(PS5_LIBDIR)
LIBS := -lkernel_sys -lkernel -lSceSystemService -lSceUserService -lSceFsInternalForVsh -lSceRegMgr -lSceNet
I18N_FILES := $(wildcard src/i18n/*.js)
PREVIEW_DIR ?= /tmp/garlic-savemgr-ui-preview
PREVIEW_PORT ?= 8082

all: garlic-savemgr.elf

.DELETE_ON_ERROR:

src/ui.h: src/ui.html src/i18n $(I18N_FILES) Makefile
	@set -e; \
	ui_tmp=$$(mktemp); \
	trap 'rm -f "$$ui_tmp"' EXIT HUP INT TERM; \
	sed 's/__VERSION__/v$(VERSION)/g' $< > "$$ui_tmp"; \
	for file in $(I18N_FILES); do sed -i '/^"__I18N_DICTIONARIES__";$$/r '"$$file" "$$ui_tmp"; done; \
	sed -i '/^"__I18N_DICTIONARIES__";$$/d' "$$ui_tmp"; \
	xxd -i -n src_ui_html "$$ui_tmp" > $@

src/sqlite3.o: src/sqlite3.c
	$(PS5_CC) -O2 -D_BSD_SOURCE -std=gnu11 -I$(PS5_INCDIR) $(SQLITE_FLAGS) -c -o $@ $<

garlic-savemgr.elf: src/main.c src/sfo_account.h src/ui.h src/sqlite3.o
	$(PS5_CC) $(CFLAGS) $(LDFLAGS) -o $@ src/main.c src/sqlite3.o $(LIBS)

clean:
	rm -f garlic-savemgr.elf src/ui.h src/sqlite3.o src/_ui_tmp.html

ui-preview: src/ui.html src/i18n $(I18N_FILES)
	mkdir -p $(PREVIEW_DIR)
	sed 's/__VERSION__/local-preview/g' src/ui.html > $(PREVIEW_DIR)/index.html
	for file in $(I18N_FILES); do sed -i '/^"__I18N_DICTIONARIES__";$$/r '"$$file" $(PREVIEW_DIR)/index.html; done
	sed -i '/^"__I18N_DICTIONARIES__";$$/d' $(PREVIEW_DIR)/index.html
	@echo "UI preview: http://127.0.0.1:$(PREVIEW_PORT)/"
	cd $(PREVIEW_DIR) && python3 -m http.server $(PREVIEW_PORT) --bind 0.0.0.0

.PHONY: all clean ui-preview
