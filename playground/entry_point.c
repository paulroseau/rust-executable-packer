#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <errno.h>

const int constant = 29;


const char* instructions = "\x48\x31\xFF\xB8\x3C\x00\x00\x00\x0F\x05";
/*
  * corresponds to:
  * 4831FF
  * B83C000000
  * 0F05
  * which corresponds to:
  * xor rdi, rdi
  * mov eax, 0x3c
  * syscall
**/

int add(int i, int j) {
  return i + j;
}

int main() {
  printf("main is at %p\n", &main);

  int numb = 13;
  printf("numb is at %p\n", &numb);
  numb = 4;
  printf("numb is %d\n", numb);

  printf("constant is at  %p\n", &constant);
  void* a_pointer = malloc(sizeof(int));
  printf("&a_pointer is at  %p\n", &a_pointer);
  printf("a_pointer is at  %p\n", a_pointer);
  free(a_pointer);

  void (*f)() = (void*) instructions; // cast instructions into a pointer to a void, and assign it to a function f
  
  size_t region = (size_t) instructions; // instructions is a pointer, casting it to an unsigned long
  region = region & (~0xfff);
  printf("page @ %p\n", region);

  printf("making instruction page executable...\n");
  int ret = mprotect((void *) region, 0x1000, PROT_READ | PROT_EXEC); // making the whole page executable
  if (ret != 0) {
    printf("mprotect failed: error %d\n", errno); // errno is a macro, don't really know how it works
    return 1;
  }
  printf("OK\n");
  printf("jumping to read-only instructions...\n");
  f();
  printf("after jump\n");

  // Fails
  printf("writing to constant...\n");
  int* constant_pointer = (int*) &constant;
  *constant_pointer = 31;
}
