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
int __stdcall func3(__int64 a) {
    __int64 b = a + 1;
    printf("%lld\n", b);
    return 1;
}

__declspec(dllexport)
__int64 __stdcall func4(int a) {
    int b = a + 1;
    printf("%d\n", b);
    return a;
}

__declspec(dllexport)
int main(void) {
    func1(1);
    func2(2);
    func3(3);
    func4(4);
    return 0;
}
