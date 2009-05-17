
all: lib
	gmcs -out:RawSocketTest.exe RawSocket.cs RawSocketNative.cs RawSocketPcap.cs RawSocketTest.cs

lib:
	gcc -Wall -Werror -fPIC -o librawsock.so -shared rawsock.c

libwin:
	i586-mingw32msvc-gcc -Wall -Werror -o rawsock.dll -shared rawsock.c -lws2_32 -Wl,--out-implib,rawsock.lib -Wl,--output-def,rawsock.def

clean:
	rm -f *.exe *.so *.dll *.lib *.def
