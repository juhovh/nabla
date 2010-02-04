CC = $(shell which gcc)
CSC = $(shell which gmcs)
CFLAGS = -Wall -Werror -Ilibtapcfg

PLATFORM      :=$(shell [ -z "$(platform)" ] && uname | tr "[A-Z]" "[a-z]" || echo "$(platform)" )
SUPPORTED_PLATFORMS=linux netbsd freebsd winnt darwin sunos

SRCS_tapcfg := libtapcfg/tapcfg.c libtapcfg/taplog.c libtapcfg/dlpi.c
SRCS_client := client/client.c client/tunnel.c client/tunnel_ipv4.c client/tunnel_ipv6.c client/tunnel_ayiya.c client/login_tic.c client/conf_aiccu.c client/compat.c client/logger.c client/hash_sha1.c client/hash_md5.c client/command.c client/tic/common.c client/tic/tic.c $(SRCS_tapcfg)

SRCS_rawsock   := server/Sockets/rawsock.c
SRCS_RawSocket := server/Sockets/RawSocket.cs server/Sockets/RawSocketNative.cs server/Sockets/RawSocketPcap.cs
SRCS_utils     := server/*.cs server/Database/*.cs
LIBS_utils     := System,System.Data,System.Data.SQLite,Nabla.Sockets
SRCS_dbeditor  := $(SRCS_utils) server/utils/DatabaseEditor.cs
SRCS_server    := $(SRCS_utils) server/utils/Server.cs

TARGET_ext :=
TARGET_libpre := lib
TARGET_libext := .so

ifeq ($(PLATFORM), winnt)
	CC := i586-mingw32msvc-gcc
	CFLAGS := -DWINVER=0x0501 $(CFLAGS)
	TARGET_ext := .exe
	TARGET_libpre :=
	TARGET_libext := .dll
else
	CFLAGS := -fPIC $(CFLAGS)
endif

ifeq ($(PLATFORM), darwin)
	TARGET_libext := .dylib
endif

LIBS_general := 
LIBS_linux := -lpthread $(LIBS_general)
LIBS_netbsd := -lpthread $(LIBS_general)
LIBS_freebsd := -lpthread $(LIBS_general)
LIBS_winnt := -lws2_32 $(LIBS_general)
LIBS_darwin := $(LIBS_unix)
LIBS_sunos := -lsocket -lnsl $(LIBS_unix)
LIBS := $(LIBS_$(PLATFORM))

LIBFLAGS_linux := -shared
LIBFLAGS_netbsd := -shared
LIBFLAGS_freebsd := -shared
LIBFLAGS_winnt := -shared -Wl,--out-implib,bin/rawsock.lib -Wl,--output-def,bin/rawsock.def
LIBFLAGS_darwin := -arch i386 -dynamiclib -install_name $(TARGET_libpre)rawsock$(TARGET_libext)
LIBFLAGS_sunos := $(LIBFLAGS_unix)
LIBFLAGS := $(LIBFLAGS_$(PLATFORM))

TARGET_client   := bin/client$(TARGET_ext)
TARGET_rawsock  := bin/$(TARGET_libpre)rawsock$(TARGET_libext)
TARGET_dbeditor := bin/DatabaseEditor.exe
TARGET_server   := bin/Server.exe


all: platform-check nabla-client nabla-server

# This makefile target will check the platform.
platform-check:
	@for plat in ${SUPPORTED_PLATFORMS} ; do \
	        [ "${PLATFORM}" = "$$plat" ] && platform_ok=xxx || platform_ok=$$platform_ok ; \
	done && ([ -z "$$platform_ok" ] && { \
	    echo ; \
	    echo "Error: Target platform <${PLATFORM}> is invalid!"; \
	    echo "Syntax: make ostype=<target platform> all"; \
	    echo ; \
	    echo "    where <target platform> is one of the following:"; \
	    echo "        linux        for Linux."          ; \
	    echo "        winnt        for Windows."          ; \
	    echo "        freebsd      for FreeBSD."        ; \
	    echo "        netbsd       for NetBSD."         ; \
	    echo "        darwin       for Mac OS X darwin."; \
	    echo "        sunos        for Sun/Solaris."    ; \
	    echo ; \
	    exit 1;\
	} || echo "Building Nabla for platform ${PLATFORM} ..." ; )

nabla-client:
ifneq ($(CC),)
	$(CC) $(CFLAGS) -o $(TARGET_client) $(SRCS_client) $(LIBS)
endif

nabla-server: nabla-rawsock
ifneq ($(CSC),)
	cp lib/* bin/
	$(CSC) -lib:bin -out:$(TARGET_server) -r:$(LIBS_utils) $(SRCS_server)
	$(CSC) -lib:bin -out:$(TARGET_dbeditor) -r:$(LIBS_utils) $(SRCS_dbeditor)
endif

nabla-rawsock:
ifneq ($(CC),)
	$(CC) $(CFLAGS) -o $(TARGET_rawsock) $(SRCS_rawsock) $(LIBFLAGS) $(LIBS)
endif
ifneq ($(CSC),)
	$(CSC) -t:library -r:System -out:bin/Nabla.Sockets.dll $(SRCS_RawSocket)
endif

clean:
	rm -f bin/client bin/*.exe bin/*.so bin/*.dll bin/*.def bin/*.lib bin/*.dylib

