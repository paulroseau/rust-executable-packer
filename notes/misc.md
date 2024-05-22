# Function pointers in C

Source: https://www.geeksforgeeks.org/function-pointer-in-c/

To declare a pointer to a function you need to use `()` to force the application
of the `*` operator to the name of the function: 
```c 
int (*foo)(int) = &main;
```

Also note that, unlike normal pointers:
- a function pointer points to code, not data. Typically a function pointer stores the start of executable code.
- using function pointers does not allocate de-allocate memory
 
A function's name can also be used to get functions' address. For example, the
two programs below are equivalent:
```c
#include <stdio.h> 
void fun(int a) { 
    printf("Value of a is %d\n", a); 
} 
  
int main() { 
    void (*fun_ptr)(int) = &fun; 
    /* The above line is equivalent of following two 
       void (*fun_ptr)(int); 
       fun_ptr = &fun;  
    */
    (*fun_ptr)(10); 
    return 0; 
} 
```
vs
```c
#include <stdio.h> 
void fun(int a) { 
    printf("Value of a is %d\n", a); 
} 
  
int main() {  
    void (*fun_ptr)(int) = fun;  // & removed 
    fun_ptr(10);  // * removed 
    return 0; 
}
```
Also:
```c
int main() {
  // will all print the same thing
  printf("&main is at %p\n", &main);
  printf("main is at %p\n", main);
  printf("*main is at %p\n", *main);
  printf("**main is at %p\n", **main);
}
```
