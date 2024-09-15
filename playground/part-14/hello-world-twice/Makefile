all: regular-hello static-hello static-pie-hello

regular-hello:
	gcc hello.c -o regular-hello

static-hello-at-address-0:
	# forces the text segment to be mapped to address 0, can then only be executed with sudo because we need to have CAP_SYS_RAWIO capability
	gcc -static hello.c -o hello -Wl,-Ttext-segment=0x0

static-hello:
	gcc -static hello.c -o static-hello

static-pie-hello:
	gcc -static-pie hello.c -o static-pie-hello

clean:
	rm regular-hello static-hello static-pie-hello

