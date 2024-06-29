# generate position independent code
CFLAGS  := -fPIC

# -Wl allows to pass argument to ld as flags
LDFLAGS :=  -nostartfiles -nodefaultlibs -L. -Wl,-rpath='$$ORIGIN'

all: chimera chimera-no-pic chimera.s chimera-no-pic.s

chimera-no-pic: chimera.c libfoonopic.so
	gcc -c chimera.c -o chimera-no-pic.o
	gcc chimera-no-pic.o -o chimera-no-pic -lfoonopic ${LDFLAGS}

chimera: chimera.c libfoo.so
	gcc -c chimera.c ${CFLAGS}
	gcc chimera.o -o chimera -lfoo ${LDFLAGS}

libfoo.so: foo.c
	gcc -c foo.c ${CFLAGS}
	gcc foo.o -shared -o libfoo.so ${LDFLAGS}

libfoonopic.so: foo.c
	gcc -c foo.c -o foonopic.o
	gcc foonopic.o -shared -o libfoonopic.so ${LDFLAGS}

chimera.s: chimera.c
	gcc -S chimera.c ${CFLAGS}

chimera-no-pic.s: chimera.c
	gcc -S chimera.c -o chimera-no-pic.s

clean:
	rm -f chimera chimera*.{o,s} *foo*.{o,so}
