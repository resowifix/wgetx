LINK_TARGET = wgetx

OBJS = wgetx.o

REBUILDABLES = $(OBJS) $(LINK_TARGET)

all : $(LINK_TARGET)

clean: 
	rm -f $(REBUILDABLES)

$(LINK_TARGET) : $(OBJS)
	cc -g -o $@ $^ -lssl -lcrypto

%.o : %.c
	cc -g  -Wall -o $@ -c $< -lssl -lcrypto

wgetx.o : wgetx.h
