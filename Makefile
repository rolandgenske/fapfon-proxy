TARGET = fapfon-proxy
OBJ = fapfon_proxy.o client.o packet.o net.o

CC = gcc
CFLAGS += -Wall -pipe -fno-strict-aliasing -D_GNU_SOURCE
ifdef DEBUG
CFLAGS += -g
else
CFLAGS += -O2 -fno-omit-frame-pointer
endif

$(TARGET): $(OBJ) Makefile
	$(CC) -o $@ $(OBJ)

$(OBJ): fapfon_proxy.h

clean:
	@ rm -f $(TARGET) $(OBJ)
