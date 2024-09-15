all: regular-what static-what static-pie-what

regular-what:
	gcc what.c -o regular-what

static-what-at-address-0:
	# forces the text segment to be mapped to address 0, can then only be executed with sudo because we need to have CAP_SYS_RAWIO capability
	gcc -static what.c -o what -Wl,-Ttext-segment=0x0

static-what:
	gcc -static what.c -o static-what

static-pie-what:
	gcc -static-pie what.c -o static-pie-what

clean:
	rm regular-what static-what static-pie-what
