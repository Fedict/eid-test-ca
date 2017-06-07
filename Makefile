all: fromcard bin/resign

CFLAGS := -g -O2 -Wall

fromcard: fromcard.c derencode.c base64encode.c
	# For Linux:
	#$(CC) $(CFLAGS) -o $@ -I/usr/include/beid/include/rsaref220 -I/usr/include/beid/rsaref220 $^ -lbeidpkcs11
	# For OS X (possibly need to change the path to the include directory):
	#$(CC) $(CFLAGS) -o $@ -I ../eid-mw/doc/sdk/include/rsaref220 -L /usr/local/lib $^ -lbeidpkcs11

bin/resign: derencode.c signdata.c resign.c
	$(CC) $(CFLAGS) -o $@ `pkg-config --cflags --libs openssl` $^

clean:
	rm fromcard
