#include <stdio.h>

int add_two(int x) {
    return x + 2;
}

int subtract_two(int x) {
    return add_two(x) - 4;
}

int fib(int n) {
    if (n == 0) return 0;
    if (n == 1) return 1;
    return fib(n-1) + fib(n-2);
}

int mut_rec1(int n) {
    if (n == 0) return 0;
    return mut_rec2(n-1);
}

int mut_rec2(int n) {
    if (n == 0) return 1;
    return mut_rec1(n-1);
}

int main() {
    fib(10);
    printf("%d\n", add_two(1000));
    printf("%d\n", subtract_two(10));
    mut_rec1(10);
}
