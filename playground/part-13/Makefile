all: two-threads

debug: two-threads-debug tcb-head

two-threads:
	gcc src/two-threads.c -pthread -o output/two-threads

two-threads-debug:
	gcc -g src/two-threads.c -pthread -o output/two-threads-debug

tcb-head:
	gcc -c -g src/tcb-head.c -o output/tcb-head.o

clean:
	rm output/*
