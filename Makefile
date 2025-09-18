# Compiler
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude

# Output Binary
TARGET = build/unresolved

# Source Files
SRC = src/main.c src/zoneloader.c src/handle_dns.c src/globals.c
ZONELOADER = src/zoneloader.c

# Default rule
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^
	#gcc -Wall -Wextra -Iinclude -o build/unresolved src/main.c src/zoneloader.c src/handle_dns.c

build/zoneloader: $(ZONELOADER)
	$(CC) $(CFLAGS) -o $@ $^


