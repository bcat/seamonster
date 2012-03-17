CFLAGS = -pedantic -Wall -Wno-missing-braces -Werror
LDFLAGS = -lmagic

objs = common.o seamonster.o worker.o
exec = seamonster

.PHONY: all clean

all: $(exec)

clean:
	rm -f $(exec) $(objs)

common.o: common.h

worker.o: common.h worker.h

seamonster.o: common.h worker.h

$(exec): $(objs)
	$(CC) $(LDFLAGS) $(objs) -o $@
