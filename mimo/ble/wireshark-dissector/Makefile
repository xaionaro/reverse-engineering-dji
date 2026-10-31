CFLAGS ?= $(shell pkg-config --cflags-only-I wireshark)
WIRESHARK_VERSION := $(shell pkg-config --modversion wireshark | cut -d. -f1,2)
PLUGIN_DIR ?= $(HOME)/.local/lib/wireshark/plugins/$(WIRESHARK_VERSION)/epan

.PHONY: build install fmt clean
build: dji-ble-message.so

install: build
	mkdir -p "$(PLUGIN_DIR)"
	cp dji-ble-message.so "$(PLUGIN_DIR)/"

%.so: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -shared $< -o $@

fmt:
	clang-format -i *.c

clean:
	rm -f *.so
