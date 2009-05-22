
CFLAGS = -Wall -Werror -Ilibtapcfg

SRCS := client/client.c client/tunnel.c client/tunnel_v4v6.c client/tunnel_ether.c client/tunnel_ayiya.c client/tunnel_v6v4.c client/login_tic.c client/conf_aiccu.c client/compat.c client/logger.c client/hash_sha1.c client/hash_md5.c client/command.c client/tic/common.c client/tic/tic.c
SRCS_tapcfg := libtapcfg/tapcfg.c libtapcfg/taplog.c libtapcfg/dlpi.c
TARGET := bin/client

ifndef OSTYPE
	OSTYPE := unix
endif

ifeq ($(OSTYPE), win)
	CC := i586-mingw32msvc-gcc
	CFLAGS := -DWINVER=0x0501 $(CFLAGS)
	TARGET := $(TARGET).exe
endif

LIBS_general := 
LIBS_win := -lws2_32 $(LIBS_general)
LIBS_unix := -lpthread $(LIBS_general)
LIBS_solaris := -lsocket -lnsl $(LIBS_unix)
LIBS := $(LIBS_$(OSTYPE))

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(SRCS_tapcfg) $(LIBS)

clean:
	rm -f bin/*.exe bin/client

