
all:
	gmcs -t:library -out:Nabla.Sockets.dll Sockets/RawSocket.cs Sockets/RawSocketNative.cs Sockets/RawSocketPcap.cs
	gmcs -out:RawSocketTest.exe -r:Nabla.Sockets RawSocketTest.cs
	gmcs -out:Server.exe -r:Nabla.Sockets Server.cs NATMapper.cs NATPacket.cs

lib:
	gcc -Wall -Werror -fPIC -o librawsock.so -shared rawsock.c

libwin:
	i586-mingw32msvc-gcc -Wall -Werror -o rawsock.dll -shared rawsock.c -lws2_32 -Wl,--out-implib,rawsock.lib -Wl,--output-def,rawsock.def

libmac:
	gcc -Wall -Werror -fPIC -o librawsock.dylib -dynamiclib rawsock.c

clean:
	rm -f *.exe *.so *.dll *.lib *.def *.dylib
