CFLAGS=-I. -Os -g

all: testRs

clobber: clean
	rm -f testRs

clean:
	rm -f reedSolomon.o

testRs: test/testRs.c reedSolomon.o
	$(CC) $(CFLAGS) -o testRs test/testRs.c reedSolomon.o

reedSolomon.o: reedSolomon.c reedSolomon.h
	$(CC) $(CFLAGS) -c reedSolomon.c
