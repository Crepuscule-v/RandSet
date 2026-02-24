CC = gcc
CXX = g++
AR = /usr/bin/ar
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic -g
DEFS = 
INCLUDES = 

%.o: %.c
	$(CC) $(CFLAGS) $(DEFS) $(INCLUDES) -c $< -o $@

libstr.a: str.o
	$(AR) rcs $@ $^

all: libstr.a

.PHONY: clean
clean:
	-rm -f *.o *.a *.cfg .*.bc
