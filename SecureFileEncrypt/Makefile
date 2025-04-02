# Compiler and options
CC=gcc
OPENSSL=/opt/homebrew/opt/openssl@3
CFLAGS=-Wall -g -std=c99 -I$(OPENSSL)/include
LDFLAGS=-L$(OPENSSL)/lib -lssl -lcrypto

# Target
all: securefileencrypt

securefileencrypt: securefileencrypt.c
	$(CC) $(CFLAGS) -o securefileencrypt securefileencrypt.c $(LDFLAGS)

clean:
	rm -f *.o securefileencrypt

