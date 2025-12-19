CFLAGS=-I. -Os -g

all: rsecTest

clobber: clean
	rm -f rsecTest

clean:
	rm -f rsec.o

rsecTest: test/rsecTest.c rsec.o
	$(CC) $(CFLAGS) -o rsecTest test/rsecTest.c rsec.o

rsec.o: rsec.c rsec.h
	$(CC) $(CFLAGS) -c rsec.c
