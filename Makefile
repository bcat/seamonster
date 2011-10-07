CFLAGS = -pedantic -Wall -Werror

objs = seamonster.o
exec = seamonster

.PHONY: all clean

all: $(exec)

clean:
	rm -f $(exec) $(objs)

$(exec): $(objs)
	$(CC) $(LDFLAGS) $(objs) -o $@