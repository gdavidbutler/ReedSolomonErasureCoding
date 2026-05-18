CFLAGS=-I. -Os -g

all: rsecTest rsecMkTest thrDspRsecTest

check: rsecTest rsecMkTest thrDspRsecTest
	./rsecTest
	./rsecMkTest
	./thrDspRsecTest

clobber: clean
	rm -f genGfTables rsecTest rsecMkTest thrDspRsecTest

clean:
	rm -f rsec.o rsecMk.o thrDspRsec.o

rsecTest: test/rsecTest.c rsec.o
	$(CC) $(CFLAGS) -o rsecTest test/rsecTest.c rsec.o

rsecMkTest: test/rsecMkTest.c rsec.o rsecMk.o ../rmd128/rmd128.o ../sha256/sha256.o ../canonicalHuffman/huf.o
	$(CC) $(CFLAGS) -I../rmd128 -I../sha256 -I../canonicalHuffman -o rsecMkTest test/rsecMkTest.c rsec.o rsecMk.o ../rmd128/rmd128.o ../sha256/sha256.o ../canonicalHuffman/huf.o

rsec.o: rsec.c rsec.h
	$(CC) $(CFLAGS) -c rsec.c

rsecMk.o: rsecMk.c rsecMk.h
	$(CC) $(CFLAGS) -c rsecMk.c

# thrDsp adapter: exposes rsec + rsecMk via the threshold-dispersal
# plugin contract defined by ../asynchronousByzantineAgreementProtocols/
# thrDsp.h (consumed by ABAP's ct04Dsp).  Header-only dependency on
# that sibling repo; no link-time dependency in this direction.
thrDspRsec.o: thrDspRsec.c thrDspRsec.h rsec.h rsecMk.h ../asynchronousByzantineAgreementProtocols/thrDsp.h
	$(CC) $(CFLAGS) -I../asynchronousByzantineAgreementProtocols -c thrDspRsec.c

thrDspRsecTest: test/thrDspRsecTest.c thrDspRsec.o rsec.o rsecMk.o thrDspRsec.h ../asynchronousByzantineAgreementProtocols/thrDsp.h ../rmd128/rmd128.o ../sha256/sha256.o
	$(CC) $(CFLAGS) -I../asynchronousByzantineAgreementProtocols -I../rmd128 -I../sha256 -o thrDspRsecTest test/thrDspRsecTest.c thrDspRsec.o rsec.o rsecMk.o ../rmd128/rmd128.o ../sha256/sha256.o

genGfTables: genGfTables.c
	$(CC) $(CFLAGS) -o genGfTables genGfTables.c
