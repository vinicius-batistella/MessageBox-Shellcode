#include <iostream>
#include <Windows.h>
#include <Lmcons.h>

int main()
{
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;

    GetUserNameA(username, &username_len);

    printf("[!] Showing the username : %s\n", username);

    printf("[!] Trying to run the MessageBox API......\n");

    MessageBoxA(NULL, username, "Attention!", 0x0);
}
