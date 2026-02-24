# corpus dir
CORPUS=../corpus

all: $(CORPUS)/a.o $(CORPUS)/a_g.o $(CORPUS)/b.o $(CORPUS)/b_g.o

# object files
$(CORPUS)/%.o: %.c
	gcc -c -o $@ $<

# object files with debug_info
$(CORPUS)/%_g.o: %.c
	gcc -g -c -o $@ $<
