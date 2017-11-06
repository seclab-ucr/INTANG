
# a lot of flags

INCLUDE_DIRS = -I. -Istrategies
CC = gcc -std=gnu99
CUSTOM_DEFINES = #-DEVALUATION# -DTEST
CFLAGS = -g -c $(CUSTOM_DEFINES) $(INCLUDE_DIRS) # -Wall 
LDFLAGS = -lnetfilter_queue -lnfnetlink -lhiredis -lev -lrt
SOURCES = main.c helper.c logging.c socket.c strategy.c cache.c dns.c dnscli.c feedback.c test.c order.c redis.c memcache.c ttl_probing.c discrepancy.c
STRATEGIES = $(shell find strategies -type f -iname '*.c')
OBJECTS = $(SOURCES:.c=.o) $(STRATEGIES:.c=.o)
EXECUTABLE = intangd

.DEFAULT_GOAL := all


# here come the tagets

all: $(SOURCES) $(STRATEGIES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@ -pthread

.c.o:
	$(CC) $(CFLAGS) $< -o $@ -pthread

#strategies/%.o: strategies/%.c
#	$(CC) $(CFLAGS) $< -o $@ -pthread

#strategies:
#	cd strategies && 

clean:
	find . -name "*.o" | xargs rm
	rm $(EXECUTABLE)

