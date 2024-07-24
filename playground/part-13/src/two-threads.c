#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

void *in_thread(void* unused) {
  while (1) {
    sleep(1);
    printf("thread %p\n", pthread_self());
  }
}

void *in_thread_0(void* unused) {
  while (1) {
    int x = 3;
    x *= 3;
    printf("thread %p\n", pthread_self());
    printf("x = %d\n", x);
    printf("&x = %p\n", &x);
    printf("===========\n");
    sleep(1);
  }
}

void *in_thread_1(void* unused) {
  while (1) {
    int x = 2;
    x += 3;
    printf("thread %p\n", pthread_self());
    printf("x = %d\n", x);
    printf("&x = %p\n", &x);
    printf("===========\n");
    sleep(1);
  }
}

int main() {
  pthread_t thread0, thread1;
  pthread_create(&thread0, NULL, in_thread_0, NULL);
  pthread_create(&thread1, NULL, in_thread_1, NULL);
  pthread_join(thread0, NULL);
  pthread_join(thread1, NULL);
}
