import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    #"   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #

    "find_kernel32:                     ;"  #
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   mov eax, fs:[ecx + 0x30]        ;"  # EAX = PEB
    "   mov eax, [eax + 0xc]            ;"  # EAX = PEB -> Ldr
    "   mov esi, [eax + 0x14]           ;"  # ESI = PEB -> Ldr.InMemOrder
    "   lodsd                           ;"  # EAX = Second module
    "   xchg eax, esi                   ;"  # EAX <=> ESI
    "   lodsd                           ;"  # EAX = Third(kernel32)
    "   mov ebx, [eax + 0x10]           ;"  # EBX = Kernel32 base address
    "   mov edx, [ebx + 0x3c]           ;"  # EDX = DOS -> e_lfanew
    "   add edx, ebx                    ;"  # EDX = PE Header
    "   mov edx, [edx + 0x78]           ;"  # EDX = Offset export table
    "   add edx, ebx                    ;"  # EDX = Export table
    "   mov esi, [edx + 0x20]           ;"  # ESI = Offset name table
    "   add esi, ebx                    ;"  # ESI = Names tables
    "   xor ecx, ecx                    ;"  # ECX = 0

    "Get_Function:                      ;"  #
    "   inc ecx                         ;"  # ECX = 1
    "   lodsd                           ;"  # Get name offset
    "   add eax, ebx                    ;"  # Get function name
    "   cmp dword ptr[eax], 0x50746547  ;"  # GetP
    "   jnz Get_Function                ;"  #
    "   cmp dword ptr[eax + 0x4], 0x41636f72;"  # rocA 
    "   jnz Get_Function                ;"  #
    "   cmp dword ptr[eax + 0x8], 0x65726464;"  # ddre
    "   jnz Get_Function                ;"  #
    "   mov esi, [edx + 0x24]           ;"  # ESi = Offset ordinals
    "   add esi, ebx                    ;"  # ESI = Ordinals table
    "   mov cx, [esi + ecx * 2]         ;"  # CX = Number of function
    "   dec ecx                         ;"  # ECX = -1
    "   mov esi, [edx + 0x1c]           ;"  # ESI = Offset address table
    "   add esi, ebx                    ;"  # ESI = Address table
    "   mov edx, [esi + ecx * 4]        ;"  # EDX = Pointer(offset)
    "   add edx, ebx                    ;"  # EDX = GetProcAddress
    "   mov [ebp], ebx                  ;"  # [EBP] = Kernel32
    "   mov [ebp + 4], edx              ;"  # [EBP+4] = GetProcAddressStub
    # "   ret                             "

    "LoadLibrary:                       ;"  #
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0
    "   push 0x41797261                 ;"  # aryA
    "   push 0x7262694c                 ;"  # Libr
    "   push 0x64616f4c                 ;"  # Load
    "   push esp                        ;"  # "LoadLibrary"
    "   push [ebp]                      ;"  # Kernel32 base address
    "   call [ebp + 4]                  ;"  # GetProcAddress(LL) | if success, LoadLibrary address should be at EAX
    "   mov [ebp + 8], eax              ;"  # [EBP+8] = LoadLibraryAStub
    # "   ret                             "

    "Load_User32.dll:                   ;" 
    "   add esp, 0xc                    ;"  # 'clean stack'
    "   pop ecx                         ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   mov cx, 0x6c6c                  ;"  # ll
    "   push ecx                        ;"  # ECX = ll -> ESP
    "   push 0x642e3233                 ;"  # 32.d
    "   push 0x72657355                 ;"  # User
    "   push esp                        ;"  # "User32.dll"
    "   call [ebp + 8]                  ;"  # LoadLibrary("User32.dll")
    "   mov [ebp + 0xC], eax            ;"  # [EBP+C] = User32.dll
    # "   ret                             "

    "Load_Advapi32.dll:                 ;"
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   push 0x6c6c642e                 ;"  # .dll
    "   push 0x32336970                 ;"  # pi32
    "   push 0x61766441                 ;"  # Adva
    "   push esp                        ;"  # "Advapi32.dll"
    "   call [ebp + 8]                  ;"  # LoadLibrary("Advapi32.dll")
    "   mov [ebp + 0x10], eax           ;"  # [EBP+10] = Advapi32.dll
    # "   ret                             "

    "GPA_GetUserNameA:                  ;"
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   push 0x41656d61                 ;"  # ameA
    "   push 0x4e726573                 ;"  # serN
    "   push 0x55746547                 ;"  # GetU
    "   push esp                        ;"  # "GetUserNameA"
    "   push [ebp + 0x10]               ;"  # Advapi32 base address
    "   call [ebp + 4]                  ;"  # GetProcAddress(GetUserNameA) | if success, GetUserNameA address should be at EAX
    "   mov [ebp + 0x14], eax           ;"  # Put GetUserNameA into [EBP+14]
    # "   ret                             "

    "GPA_MessageBoxA:                   ;"
    "   xor ecx, ecx                    ;"  # ECX = 0
    "   push ecx                        ;"  # ECX = 0 -> ESP
    "   mov ecx, 0xffbe8791             ;"  # oxA
    "   neg ecx                         ;"  # -oxA
    "   push ecx                        ;"  # ECX -> ESP
    "   push 0x42656761                 ;"  # ageB
    "   push 0x7373654d                 ;"  # Mess
    "   push esp                        ;"  # "MessageBoxA"
    "   push [ebp + 0xC]                ;"  # User32 base address
    "   call [ebp + 4]                  ;"  # GetProcAddress(MessageBoxA) | if success, MessageBoxA address should be at EAX
    "   mov [ebp + 0x18], eax           ;"  # Put MessageBox into [EBP+18]

    "Call_GetUserNameA:                 ;"
    "   sub esp, 0x0A                   ;"  # ESP - 0x0A (10)
    "   mov edx, esp                    ;"  # ESP -> EDX
    "   mov [ebp + 0x1C], edx           ;"  # [EBP + 0x1C] = Username
    "   sub esp, 0x0A                   ;"  # ESP - 0x0A (10) - Saves another area to store the pointer
    "   mov ecx, esp                    ;"  # ESP -> ECX
    "   push ecx                        ;"  # ECX -> ESP
    "   push edx                        ;"  # EDX -> ESP
    "   call [ebp + 0x14]               ;"  # GetUserNameA
    # "   ret                             "

    "Call_MessageBox:                   ;"
    "   xor eax, eax                    ;"  # EAX = 0
    "   inc eax                         ;"  # EAX = 1
    "   push eax                        ;"  # EAX -> ESP
    "   dec eax                         ;"  # EAX = 0
    "   push eax                        ;"  # EAX -> ESP
    "   push [ebp + 0x1C]               ;"  # 'username' -> ESP
    "   push eax                        ;"  # EAX -> ESP
    "   call [ebp + 0x18]               ;"  # MessageBox
    "   ret                             "

)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))