CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS_RSA = -lgmp -lcrypto
LIBS_ECDH = -lsodium

# Targets
TARGETS = rsa_assign_2 ecdh_assign_2

# Default target
all: $(TARGETS)

# RSA program
rsa_assign_2: rsa_assign_2.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS_RSA)

# ECDH program
ecdh_assign_2: ecdh_assign_2.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS_ECDH)

# Clean build files
clean:
	rm -f $(TARGETS) *.o

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install libgmp-dev libssl-dev libsodium-dev

# Install dependencies (macOS with Homebrew)
install-deps-macos:
	brew install gmp openssl libsodium

# Phony targets
.PHONY: all clean install-deps install-deps-macos
