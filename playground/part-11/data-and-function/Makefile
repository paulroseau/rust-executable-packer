# generate position independent code
CFLAGS  := -fPIC

# -Wl allows to pass argument to ld as flags
LDFLAGS :=  -nostartfiles -nodefaultlibs -L. -Wl,-rpath='$$ORIGIN'

all: chimera chimera.s

chimera: chimera.c libfoo.so libbar.so
	gcc -c chimera.c ${CFLAGS}
	gcc chimera.o -o chimera -lfoo -lbar ${LDFLAGS}

libfoo.so: foo.c
	gcc -c foo.c ${CFLAGS}
	gcc foo.o -shared -o libfoo.so ${LDFLAGS}

libbar.so: bar.c
	gcc -c bar.c ${CFLAGS}
	gcc bar.o -shared -o libbar.so ${LDFLAGS}

chimera.s: chimera.c
	gcc -S chimera.c ${CFLAGS}

clean:
	rm -f chimera chimera*.{o,s} *foo*.{o,so} *bar*.{o,so}
