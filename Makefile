CFLAGS=-I. -Os -g

all: rsecTest rsecMkTest

check: rsecTest rsecMkTest
	./rsecTest
	./rsecMkTest

clobber: clean
	rm -f genGfTables rsecTest rsecMkTest

clean:
	rm -f rsec.o rsecMk.o

rsecTest: test/rsecTest.c rsec.o
	$(CC) $(CFLAGS) -o rsecTest test/rsecTest.c rsec.o

rsecMkTest: test/rsecMkTest.c rsec.o rsecMk.o ../rmd128/rmd128.o ../sha256/sha256.o ../canonicalHuffman/huf.o
	$(CC) $(CFLAGS) -I../rmd128 -I../sha256 -I../canonicalHuffman -o rsecMkTest test/rsecMkTest.c rsec.o rsecMk.o ../rmd128/rmd128.o ../sha256/sha256.o ../canonicalHuffman/huf.o

rsec.o: rsec.c rsec.h
	$(CC) $(CFLAGS) -c rsec.c

rsecMk.o: rsecMk.c rsecMk.h
	$(CC) $(CFLAGS) -c rsecMk.c

genGfTables: genGfTables.c
	$(CC) $(CFLAGS) -o genGfTables genGfTables.c
