OS := $(shell uname)

ifeq ($(OS), Darwin)
    SO_EXT := dylib
else
    SO_EXT := so
endif

OPENRESTY_PREFIX ?= /usr/local/openresty
LUA_LIB_DIR      ?= $(OPENRESTY_PREFIX)/site/lualib
INSTALL_SOFT     ?= ln -s
INSTALL          ?= install
CURL             ?= curl
RESTY_BINDIR      = $(OPENRESTY_PREFIX)/bin
OPM               = $(RESTY_BINDIR)/opm
OPM_LIB_DIR      ?= $(OPENRESTY_PREFIX)/site
PWD               = `pwd`
LUAROCKS         ?= luarocks

LIBS       = waf waf.lua
C_LIBS     = lua-aho-corasick libinjection lua-resty-hyperscan
OPM_LIBS   = hamishforbes/lua-resty-iputils p0pr0ck5/lua-resty-cookie \
	p0pr0ck5/lua-ffi-libinjection p0pr0ck5/lua-resty-logger-socket
MAKE_LIBS  = $(C_LIBS) decode
SO_LIBS    = libac.so libinjection.so  libdecode.so libwhs.so
RULES      = rules
ROCK_DEPS  = "lrexlib-pcre 2.7.2-1" busted luafilesystem

SBOX_UTIL_LINK = https://raw.githubusercontent.com/mozilla-services/lua_sandbox_extensions/main/heka/modules/heka/util.lua

LOCAL_LIB_DIR = lib/resty

.PHONY: all test install clean \
test-unit test-acceptance test-regression test-translate test-lua-resty-hyperscan \
lua-aho-corasick libinjection lua-resty-hyperscan \
clean-libinjection clean-lua-aho-corasick clean-lua-resty-hyperscan install-opm-libs clean-opm-libs transform_coreruleset

all: $(MAKE_LIBS) debug-macro

clean: clean-libinjection clean-lua-aho-corasick \
	clean-decode clean-libs clean-test clean-debug-macro clean-lua-resty-hyperscan

clean-debug-macro:
	./tools/debug-macro.py clean

clean-install: clean-deps
	cd $(LUA_LIB_DIR) && rm -rf $(RULES) && rm -f $(SO_LIBS) && cd resty/ && \
		rm -rf $(LIBS)

clean-decode:
	cd src && make clean

clean-deps: clean-opm-libs clean-rocks clean-ext-deps

clean-lua-aho-corasick:
	cd lua-aho-corasick && make clean

clean-libinjection:
	cd libinjection && make clean && git checkout -- .

clean-lua-resty-hyperscan:
	cd lua-resty-hyperscan && make clean
	rm -f lib/resty/hyperscan.lua

clean-libs:
	cd lib && rm -f $(SO_LIBS)

clean-opm-libs:
	$(OPM) --install-dir=$(OPM_LIB_DIR) remove $(OPM_LIBS)

clean-rocks:
	for ROCK in $(ROCK_DEPS); do \
		$(LUAROCKS) remove $$ROCK; \
	done

clean-ext-deps:
	rm -f /tmp/sboxutil_temp.lua

clean-test:
	rm -rf t/servroot*

transform_coreruleset:
	./tools/parser.py
	node --experimental-specifier-resolution=node --loader ts-node/esm search_init_schema.ts

debug-macro:
	./tools/debug-macro.py

decode:
	cd src/ && make
	cp src/libdecode.so lib/

lua-aho-corasick:
	cd $@ && make
	cp $@/libac.$(SO_EXT) lib/libac.so

libinjection:
	cd $@ && make all
	cp $@/src/$@.so lib/

lua-resty-hyperscan:
	cd $@ && make
	cp $@/lib/resty/hyperscan.lua lib/resty
	cp $@/hs_wrapper/libwhs.so lib

test-unit:
	PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove -r ./t/unit

test-acceptance:
	PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove -r ./t/acceptance

test-regression:
	PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove -r ./t/regression

test-translate:
	prove -r ./t/translate/

test-lua-aho-corasick:
	cd lua-aho-corasick && make test

test-libinjection:
	cd libinjection && make check

test-lua-resty-hyperscan:
	cd lua-resty-hyperscan && make test

test: clean all test-unit test-acceptance test-regression test-translate

test-libs: clean all test-lua-aho-corasick \
	test-libinjection test-lua-resty-hyperscan

test-recursive: test test-libs

test-fast: all
	TEST_NGINX_RANDOMIZE=1 PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove \
		-j16 -r ./t/translate
	TEST_NGINX_RANDOMIZE=1 PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove \
		-j16 -r ./t/unit
	TEST_NGINX_RANDOMIZE=1 PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove \
		-j16 -r ./t/regression
	TEST_NGINX_RANDOMIZE=1 PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove \
		-j4 -r ./t/acceptance
	tools/rebusted -k -o=TAP ./t/translation/*
	./tools/lua-releng -L

.PHONY:test-sercules-language
test-sercules-language:
	tools/rebusted  test-cases/*

install-check:
	stat lib/*.so > /dev/null

install-deps: install-opm-libs install-rocks install-ext-deps

install-opm-libs:
	$(OPM) --install-dir=$(OPM_LIB_DIR) get $(OPM_LIBS)

install-rocks:
	for ROCK in $(ROCK_DEPS); do \
		$(LUAROCKS) install $$ROCK; \
	done

install-ext-deps: clean-ext-deps
	$(CURL) -SL -o /tmp/sboxutil_temp.lua $(SBOX_UTIL_LINK)
	$(INSTALL) -m 644 /tmp/sboxutil_temp.lua $(LUA_LIB_DIR)/util.lua

install-link: install-check
	$(INSTALL_SOFT) $(PWD)/lib/resty/* $(LUA_LIB_DIR)/resty/
	$(INSTALL_SOFT) $(PWD)/lib/*.so $(LUA_LIB_DIR)
	$(INSTALL_SOFT) $(PWD)/rules/ $(LUA_LIB_DIR)

install: install-check install-deps
	$(INSTALL) -d $(LUA_LIB_DIR)/resty/waf/storage
	$(INSTALL) -d $(LUA_LIB_DIR)/rules
	$(INSTALL) -m 644 lib/resty/*.lua $(LUA_LIB_DIR)/resty/
	$(INSTALL) -m 644 lib/resty/waf/*.lua $(LUA_LIB_DIR)/resty/waf/
	$(INSTALL) -m 644 lib/resty/waf/storage/*.lua $(LUA_LIB_DIR)/resty/waf/storage/
	$(INSTALL) -m 644 lib/*.so $(LUA_LIB_DIR)
	$(INSTALL) -m 644 rules/*.json $(LUA_LIB_DIR)/rules/

install-soft: install-check install-deps install-link
