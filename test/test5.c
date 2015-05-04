#include <stdio.h>

__declspec(dllexport)
int __cdecl func1(__int64 a) {
    __int64 b = a + 1;
    printf("%lld\n", b);
    return 1;
}

__declspec(dllexport)
__int64 __cdecl func2(int a) {
    int b = a + 1;
    printf("%d\n", b);
    return a;
}

__declspec(dllexport)
int __cdecl func3(char a) {
    int b = a + 1;
    printf("%d\n", b);
    return a;
}

__declspec(dllexport)
int __stdcall func4(__int64 a) {
    __int64 b = a + 1;
    printf("%lld\n", b);
    return 1;
}

__declspec(dllexport)
__int64 __stdcall func5(int a) {
    int b = a + 1;
    printf("%d\n", b);
    return a;
}

__declspec(dllexport)
int __stdcall func6(char a) {
    int b = a + 1;
    printf("%d\n", b);
    return a;
}

__declspec(dllexport)
int main(void) {
    func1(-1);
    func2(-2);
    func3(-3);
    func4(-4);
    func5(-5);
    func6(-6);
    return 0;
}
