TARGET = fapfon-proxy
OBJ = fapfon_proxy.o client.o packet.o net.o

CC = gcc
CFLAGS += -Wall -pipe -fno-strict-aliasing -D_GNU_SOURCE -DOSREV=2600
ifdef DEBUG
CFLAGS += -g
else
CFLAGS += -O2 -fno-omit-frame-pointer
endif

$(TARGET): $(OBJ) Makefile
	$(CC) -o $@ $(OBJ)

clean:
	@ rm -f $(TARGET) $(OBJ)

fapfon_proxy.o: fapfon_proxy.h

client.o: fapfon_proxy.h

packet.o: fapfon_proxy.h

net.o: fapfon_proxy.h
