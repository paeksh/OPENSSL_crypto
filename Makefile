OPENSSL = $(shell brew --prefix openssl@3)

cryp: cryp.c
	gcc -o cryp cryp.c -lssl -lcrypto
clean: 
	rm -f cryp