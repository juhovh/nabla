
all:
	gmcs -t:library -out:Nabla.Sockets.dll Sockets/RawSocket.cs Sockets/RawSocketNative.cs Sockets/RawSocketPcap.cs
	gmcs -out:RawSocketTest.exe -r:Nabla.Sockets RawSocketTest.cs
	gmcs -out:ParallelDeviceTest.exe -r:Nabla.Sockets ParallelDeviceTest.cs ParallelDevice.cs

lib:
	gcc -Wall -Werror -fPIC -o librawsock.so -shared Sockets/rawsock.c

libwin:
	i586-mingw32msvc-gcc -Wall -Werror -o rawsock.dll -shared Sockets/rawsock.c -lws2_32 -Wl,--out-implib,rawsock.lib -Wl,--output-def,rawsock.def

libmac:
	gcc -Wall -Werror -fPIC -o librawsock.dylib -dynamiclib Sockets/rawsock.c

clean:
	rm -f *.exe *.so *.dll *.lib *.def *.dylib
