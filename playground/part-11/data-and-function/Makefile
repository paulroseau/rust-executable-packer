# generate position independent code
CFLAGS  := -fPIC

# -Wl allows to pass argument to ld as flags
LDFLAGS :=  -nostartfiles -nodefaultlibs -L. -Wl,-rpath='$$ORIGIN'

all: chimera chimera.s

chimera: chimera.c libfoo.so libbar.so
	gcc -c chimera.c ${CFLAGS}
	# This does not work because the linker does one pass on dependencies so since
	# lbar depends on lfoo, it needs to come before
	# gcc chimera.o -o chimera -lfoo -lbar ${LDFLAGS}
	gcc chimera.o -o chimera -lbar -lfoo ${LDFLAGS}

static-chimera: libfoo.a libbar.a
	gcc -c chimera.c ${CFLAGS}
	gcc -static chimera.o -o static-chimera -nostartfiles -nodefaultlibs -L . -lbar -lfoo

libfoo.a: foo.c
	gcc -c foo.c ${CFLAGS}
	ar rs libfoo.a foo.o

libbar.a: bar.c
	gcc -c bar.c ${CFLAGS}
	ar rs libbar.a bar.o

libfoo.so: foo.c
	gcc -c foo.c ${CFLAGS}
	gcc foo.o -shared -o libfoo.so ${LDFLAGS}

libbar.so: bar.c
	gcc -c bar.c ${CFLAGS}
	gcc bar.o -shared -o libbar.so ${LDFLAGS}

chimera.s: chimera.c
	gcc -S chimera.c ${CFLAGS}

clean:
	rm -f chimera chimera*.{a,o,s} *foo*.{a,o,so} *bar*.{a,o,so}
