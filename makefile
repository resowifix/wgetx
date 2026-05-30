LINK_TARGET = wgetx wgetx_rec

OBJS = wgetx.o setx.o wgetx_util.o wgetx_rec.o

REBUILDABLES = $(OBJS) $(LINK_TARGET)

all : $(LINK_TARGET)

clean: 
	rm -f $(REBUILDABLES)

$(LINK_TARGET) : $(OBJS)
	cc -g -o $@ $^ -lssl -lcrypto

%.o : %.c
	cc -g  -Wall -o $@ -c $< -lssl -lcrypto

setx.o : setx.h

wgetx_util.o : wgetx.h setx.h

wgetx.o : wgetx.h

wgetx_rec.o : wgetx.h setx.h
