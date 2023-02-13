LIBS = -lpcap -lpthread

BIN = sniffer

SRCS = sniffer.c

ifeq ($(BUILD_MODE),debug)
	TARGET=build/debug
	CFLAGS += -g
else
	TARGET=build/default
	CFLAGS += -O2
endif

all: $(BIN)

$(BIN): $(SRCS)
	mkdir -p $(TARGET)
	g++ $(CFLAGS) -Wall -fmessage-length=0 -o $(TARGET)/$(BIN) $(SRCS) $(LIBS)

clean:
	rm -f build/*/$(BIN)
