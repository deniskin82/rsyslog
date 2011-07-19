all: libtest.so.1.0 main

clean:
	rm -f *.o *.so.1.0 main /lib/libtest.so.1.0

main: main.o libtest.so.1.0
	gcc -ldl -o main main.o -ltest

lib.o:	lib.c
	gcc -Wall -fPIC -c lib.c

main.o:	main.c
	gcc -Wall -c main.c

libtest.so.1.0: lib.o
	gcc -shared -Wl,-soname,libtest.so.1 -o libtest.so.1.0 lib.o
	mv libtest.so.1.0 /lib
	rm -f /lib/libtest.so
	rm -f /lib/libtest.so.1
	ln -sf /lib/libtest.so.1.0 /lib/libtest.so
	ln -sf /lib/libtest.so.1.0 /lib/libtest.so.1
