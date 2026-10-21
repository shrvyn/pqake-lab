#include <stdio.h>
#include <stdint.h>
#include <time.h>

int main(void) {
    printf("sizeof(void*)=%zu  %s\n", sizeof(void *), sizeof(void *) == 8 ? "x86-64" : "other");
    uint64_t x = 0x123456789abcdefull;
    __asm__ volatile("mov %0, %%rax" : : "r"(x) : "rax");
    printf("inline asm ok, %lu\n", (unsigned long)x);
    return 0;
}
