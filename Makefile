CFLAGS = -pedantic -Wall -Wno-missing-braces -Werror -g
LDFLAGS = -lmagic -g

objs = common.o conn.o fs.o req.o resfail.o resfile.o resmenu.o seamonster.o \
			 worker.o
exec = seamonster

.PHONY: all clean

all: $(exec)

clean:
	rm -f $(exec) $(objs)

common.o: common.h

fs.o: common.h fs.h

req.o: req.h

req.h: conn.h

resfail.o: common.h resfail.h

resfail.h: conn.h

resfile.o: common.h resfile.h

resfile.h: conn.h

resmenu.o: common.h resmenu.h

resmenu.h: conn.h

worker.o: common.h conn.h fs.h req.h resfail.h resfile.h resmenu.h worker.h

seamonster.o: common.h worker.h

$(exec): $(objs)
	$(CC) $(LDFLAGS) $(objs) -o $@
