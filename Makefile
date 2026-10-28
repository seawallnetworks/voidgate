# voidgate
CC      ?= gcc
CLANG   ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
# The Seawall stack's prefix, which it shares with mini-fw, sw_authd...
PREFIX  ?= /usr/local/seawall
CONFDIR ?= $(PREFIX)/etc/voidgate
# sw_flowd's header, <sw_flowd/sw_flowd.h>: the flow table voidgate reads
# (sw_flowd's "make install-header" puts it there)
SW_FLOWD_PREFIX ?= $(PREFIX)
SW_FLOWD_H := $(SW_FLOWD_PREFIX)/include/sw_flowd/sw_flowd.h
# libpkt, the stack's packet parser (Seawall proposal 0010):
# <libpkt/parse.h>, which libpkt's "make install" puts there
LIBPKT_PREFIX ?= $(PREFIX)
LIBPKT_H := $(LIBPKT_PREFIX)/include/libpkt/parse.h
# libsw, the stack's userspace library (Seawall proposal 0011): logging,
# readiness, the config reader, the control socket, bpffs and interface
# lookups; libsw_bpf.a, tcx and libbpf's and libxdp's messages. Linked in
# by path, as libbpf.a
LIBSW_PREFIX ?= $(PREFIX)
LIBSW_A := $(LIBSW_PREFIX)/lib/libsw.a
# libbpf's and libxdp's helpers, linked before libsw.a, which they log
# through
LIBSW_BPF_A := $(LIBSW_PREFIX)/lib/libsw_bpf.a
# The stack's OpenResty's site lualib; another OpenResty, Kong / APISIX:
# point at their Lua path.
LUA_DIR ?= $(PREFIX)/openresty/site/lualib
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
# Debian and Ubuntu keep asm/ under /usr/include/<multiarch>; Amazon
# Linux and RHEL have none, and keep it in /usr/include
MULTIARCH ?= $(shell $(CC) -print-multiarch 2>/dev/null)

SRC     := src
BPFDIR  := src/bpf
CFLAGS  := -O2 -g -Wall -Wextra -Wno-unused-parameter -MMD -MP \
	-I$(SRC) -I$(BPFDIR) -I$(SW_FLOWD_PREFIX)/include \
	-I$(LIBSW_PREFIX)/include -DVG_CONF_PATH='"$(CONFDIR)/voidgate.conf"'
# libxdp and libbpf linked in statically, so voidgate needs neither on the
# machine (libxdp carries its dispatcher in it); libelf and zlib (and
# libzstd) they need stay shared
LDFLAGS := $(patsubst -lbpf,-l:libbpf.a,$(patsubst -lxdp,-l:libxdp.a, \
	$(or $(shell pkg-config --static --libs libxdp 2>/dev/null), \
	-lxdp -lbpf -lelf -lz)))
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	-I$(SRC) -I$(BPFDIR) -I$(SW_FLOWD_PREFIX)/include \
	-I$(LIBPKT_PREFIX)/include \
	-Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-MMD -MP \
	$(if $(MULTIARCH),-isystem /usr/include/$(MULTIARCH))

USER_OBJS := src/voidgate.o src/config.o src/policy.o src/maps.o src/ipaddr.o \
	src/ctl_server.o src/http.o src/log.o
CTL_OBJS  := src/voidgatectl.o

.PHONY: all clean install install-lua uninstall test

all: voidgate voidgatectl t/unit/policy t/unit/cidr

$(BPFDIR)/voidgate.bpf.o: $(BPFDIR)/voidgate.bpf.c $(BPFDIR)/voidgate.h \
		$(SW_FLOWD_H) $(LIBPKT_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(SW_FLOWD_H):
	@echo "$@ missing: install sw_flowd's header first" \
		"(make -C ../sw_flowd install-header), or set SW_FLOWD_PREFIX" >&2
	@exit 1

$(LIBPKT_H):
	@echo "$@ missing: install libpkt first" \
		"(make -C ../libpkt install), or set LIBPKT_PREFIX" >&2
	@exit 1

$(LIBSW_A) $(LIBSW_BPF_A):
	@echo "$@ missing: install libsw first" \
		"(make -C ../libsw install), or set LIBSW_PREFIX" >&2
	@exit 1

$(USER_OBJS) $(CTL_OBJS): | $(LIBSW_A) $(LIBSW_BPF_A)

$(BPFDIR)/voidgate.skel.h: $(BPFDIR)/voidgate.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

src/voidgate.o src/maps.o src/policy.o: \
	$(BPFDIR)/voidgate.skel.h

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

voidgate: $(USER_OBJS) $(LIBSW_BPF_A) $(LIBSW_A)
	$(CC) $(CFLAGS) -o $@ $(USER_OBJS) $(LIBSW_BPF_A) $(LIBSW_A) $(LDFLAGS)

voidgatectl: $(CTL_OBJS) $(LIBSW_A)
	$(CC) $(CFLAGS) -o $@ $(CTL_OBJS) $(LIBSW_A)

t/unit/policy: t/unit/policy.c src/policy.c src/policy.h \
	src/log.h src/config.h src/maps.h src/ipaddr.h \
	$(BPFDIR)/voidgate.h src/config.o src/ipaddr.o src/log.o $(LIBSW_A)
	$(CC) $(CFLAGS) -DVG_CTRL_TEST -MF t/unit/policy.d -o $@ \
		t/unit/policy.c src/policy.c src/config.o src/ipaddr.o \
		src/log.o $(LIBSW_A)

t/unit/cidr: t/unit/cidr.c src/config.o src/ipaddr.o src/log.o $(LIBSW_A)
	$(CC) $(CFLAGS) -MF t/unit/cidr.d -o $@ t/unit/cidr.c src/config.o \
		src/ipaddr.o src/log.o $(LIBSW_A)

# Unit tests, then verdicts: real daemon + t/*.t (needs root), once for
# each hook, so XDP and TC judge the same frames alike.
test: all
	./t/unit/policy
	./t/unit/cidr
	sudo t/bin/run
	sudo VG_HOOK=tc t/bin/run
	sudo VG_HOOK=tc SW_NO_TCX=1 t/bin/run

clean:
	rm -f voidgate voidgatectl t/unit/policy t/unit/cidr t/unit/*.d \
		src/*.o src/*.d \
		$(BPFDIR)/voidgate.bpf.o $(BPFDIR)/voidgate.bpf.d \
		$(BPFDIR)/voidgate.skel.h

-include $(USER_OBJS:.o=.d) $(CTL_OBJS:.o=.d) t/unit/policy.d t/unit/cidr.d \
	 $(BPFDIR)/voidgate.bpf.d

# The config is made on the first start, by voidgate-mkconf from the
# default in share/voidgate: an install never replaces the operator's,
# and each machine gets its own interface. The unit runs
# /usr/local/seawall/sbin/voidgate whatever PREFIX is. The unit gives the
# control socket to the group voidgate (-g), from the seawall repo;
# without it (checked unless staging into DESTDIR) only root could
# connect, so nothing is installed.
install: all install-lua
	[ -n "$(DESTDIR)" ] || getent group voidgate >/dev/null || { \
		echo "group voidgate missing: install seawall first" >&2; \
		exit 1; }
	install -D -m 0755 voidgate $(DESTDIR)$(PREFIX)/sbin/voidgate
	install -D -m 0755 voidgatectl $(DESTDIR)$(PREFIX)/bin/voidgatectl
	install -D -m 0755 voidgate-mkconf \
		$(DESTDIR)$(PREFIX)/libexec/voidgate-mkconf
	install -D -m 0644 configs/voidgate.conf \
		$(DESTDIR)$(PREFIX)/share/voidgate/voidgate.conf
	install -d -m 0755 $(DESTDIR)$(CONFDIR)
	install -D -m 0644 voidgate.service \
		$(DESTDIR)/etc/systemd/system/voidgate.service

# keeps $(CONFDIR): the configuration outlives the program
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/voidgate \
		$(DESTDIR)$(PREFIX)/bin/voidgatectl \
		$(DESTDIR)$(PREFIX)/libexec/voidgate-mkconf \
		$(DESTDIR)$(PREFIX)/share/voidgate/voidgate.conf \
		$(DESTDIR)/etc/systemd/system/voidgate.service \
		$(DESTDIR)$(LUA_DIR)/resty/voidgate.lua
	-rmdir $(DESTDIR)$(PREFIX)/share/voidgate

install-lua:
	install -d $(DESTDIR)$(LUA_DIR)/resty
	install -m 0644 lua/resty/voidgate.lua $(DESTDIR)$(LUA_DIR)/resty/voidgate.lua
