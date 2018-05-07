GCC=gcc
LD=gcc
GCC_OPT=

EXECUTABLES=lbm_user load_filter test_program.so

all: $(EXECUTABLES)

lbm_user : lbm_user.o
	$(LD) -o $@ $<

load_filter : load_filter.o
	$(LD) -o $@ $< -ldl

test_program.so : test_program.o
	$(LD) -shared -fpic -fpie -o $@ $<

%.o : %.c
	$(GCC) $(GCC_OPT) -o $@ -c $< 

clean:
	rm -f $(EXECUTABLES) *.o *.so

.PHONY : all clean
