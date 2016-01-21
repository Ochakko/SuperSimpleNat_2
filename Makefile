OBJS=main.o castnet.o checksum.o initdevice.o timeexceeded.o debugprint.o convmac.o convport.o convip.o
CFLAGS=-Wall -O2
LDLIBS=-lpthread
TARGET=supersimplenat

.SUFIXES: .c .o

.PHONY: all
all: $(TARGET)

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(LDLIBS) $^

.c.o:
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

