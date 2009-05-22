
CC = $(shell which gcc)
CSC = $(shell which gmcs)
CFLAGS = -Wall -Werror -Ilibtapcfg

SRCS_tapcfg := libtapcfg/tapcfg.c libtapcfg/taplog.c libtapcfg/dlpi.c
SRCS_client := client/client.c client/tunnel.c client/tunnel_v4v6.c client/tunnel_ether.c client/tunnel_ayiya.c client/tunnel_v6v4.c client/login_tic.c client/conf_aiccu.c client/compat.c client/logger.c client/hash_sha1.c client/hash_md5.c client/command.c client/tic/common.c client/tic/tic.c $(SRCS_tapcfg)

SRCS_rawsock   := server/Sockets/rawsock.c
SRCS_RawSocket := server/Sockets/RawSocket.cs server/Sockets/RawSocketNative.cs server/Sockets/RawSocketPcap.cs
SRCS_server    := server/Server.cs server/NATMapper.cs server/NATPacket.cs

TARGET_ext :=
TARGET_libpre := lib
TARGET_libext := .so

ifndef OSTYPE
	OSTYPE := unix
endif

ifeq ($(OSTYPE), win)
	CC := i586-mingw32msvc-gcc
	CFLAGS := -DWINVER=0x0501 $(CFLAGS)
	TARGET_ext := .exe
	TARGET_libpre :=
	TARGET_libext := .dll
endif

ifeq ($(OSTYPE), osx)
	TARGET_libext := .dylib
endif

LIBS_general := 
LIBS_win := -lws2_32 $(LIBS_general)
LIBS_unix := -lpthread $(LIBS_general)
LIBS_osx := $(LIBS_unix)
LIBS_sunos := -lsocket -lnsl $(LIBS_unix)
LIBS := $(LIBS_$(OSTYPE))

LIBFLAGS_win := -shared -Wl,--out-implib,bin/rawsock.lib -Wl,--output-def,bin/rawsock.def
LIBFLAGS_unix := -shared
LIBFLAGS_osx := -dynamiclib
LIBFLAGS_sunos := $(LIBFLAGS_unix)
LIBFLAGS := $(LIBFLAGS_$(OSTYPE))

TARGET_client  := bin/client$(TARGET_ext)
TARGET_rawsock := bin/$(TARGET_libpre)rawsock$(TARGET_libext)
TARGET_server  := bin/Server.exe

all:
ifneq ($(CSC),)
	$(CC) $(CFLAGS) -o $(TARGET_client) $(SRCS_client) $(LIBS)
	$(CC) $(CFLAGS) -o $(TARGET_rawsock) $(SRCS_rawsock) $(LIBFLAGS) $(LIBS)
endif
ifneq ($(CSC),)
	$(CSC) -t:library -r:System -out:bin/Nabla.Sockets.dll $(SRCS_RawSocket)
	$(CSC) -lib:bin/ -out:$(TARGET_server) -r:System,Nabla.Sockets $(SRCS_server)
endif

clean:
	rm -f bin/client bin/*.exe bin/*.so bin/*.dll bin/*.def bin/*.lib

