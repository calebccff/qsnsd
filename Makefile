OUT := qsnsd
CC = gcc

CFLAGS += -Wall -g -O2 -I/usr/include
LDFLAGS += -lqrtr -lpthread

# the generated files must first!
SRCS := qmi_sns.c qsnsd.c qmi_tlv.c util.c
OBJS := $(SRCS:.c=.o)

$(OUT): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.c: %.qmi
	qmic -a -o . -f $<

clean:
	rm -f $(OUT) $(OBJS)

