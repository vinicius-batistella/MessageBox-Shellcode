#include <iostream>
#include <Windows.h>
#include <Lmcons.h>

typedef BOOL(WINAPI *GPA_GetUserNameA)(LPSTR, LPDWORD);

typedef int(WINAPI *GPA_MessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

int main()
{
    HMODULE Advapi32 = LoadLibraryA("Advapi32.dll");

    printf("[*] DLL found! Advapi32.dll: 0x%i\n", Advapi32);

    HMODULE User32 = LoadLibraryA("User32.dll");

    printf("[*] DLL found! User32.dll: 0x%i\n", User32);

    printf("[!] Trying to run the Getusername API......\n");

    GPA_GetUserNameA FunctionPointer_GetuserName;
    
    FunctionPointer_GetuserName = (GPA_GetUserNameA)GetProcAddress(Advapi32, "GetUserNameA");

    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;

    FunctionPointer_GetuserName(username, &username_len);

    printf("[!] Showing the username : %s\n", username);

    printf("[!] Trying to run the MessageBox API......\n");

    GPA_MessageBox FunctionPointer_MessageBox;

    FunctionPointer_MessageBox = (GPA_MessageBox)GetProcAddress(User32, "MessageBoxA");

    FunctionPointer_MessageBox(NULL, (LPCTSTR)username, (LPCTSTR)"Attention!", 0x0);
}
