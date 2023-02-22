// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "minhook/include/MinHook.h"
#include "SylantStrike.h"

DWORD WINAPI InitHooksThread(LPVOID param) {

    //MinHook itself requires initialisation, lets do this
    //before we hook specific API calls.
    if (MH_Initialize() != MH_OK) {
        OutputDebugString(TEXT("Failed to initalize MinHook library\n"));
        return -1;
    }

    //Now that we have initialised MinHook, lets prepare to hook NtProtectVirtualMemory from ntdll.dll
    MH_STATUS status = MH_CreateHookApi(TEXT("ntdll"), "NtAllocateVirtualMemory", NtAllocateVirtualMemory,
        reinterpret_cast<LPVOID*>(&pOriginalNtAllocateVirtualMemory));

    status = MH_CreateHookApi(TEXT("ntdll"), "NtWriteVirtualMemory", NtWriteVirtualMemory,
        reinterpret_cast<LPVOID*>(&pOriginalNtWriteVirtualMemory));

    status = MH_CreateHookApi(TEXT("ntdll"), "NtProtectVirtualMemory", NtProtectVirtualMemory, 
        reinterpret_cast<LPVOID*>(&pOriginalNtProtectVirtualMemory)); 

    status = MH_CreateHookApi(TEXT("ntdll"), "NtCreateThreadEx", NtCreateThreadEx,
        reinterpret_cast<LPVOID*>(&pOriginalNtCreateThreadEx));

    //Enable our hooks so they become active
    status = MH_EnableHook(MH_ALL_HOOKS);

    return status;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        //We are not interested in callbacks when a thread is created
        DisableThreadLibraryCalls(hModule);

        //We need to create a thread when initialising our hooks since
        //DllMain is prone to lockups if executing code inline.
        HANDLE hThread = CreateThread(nullptr, 0, InitHooksThread, nullptr, 0, nullptr);
        if (hThread != nullptr) {
            CloseHandle(hThread);
        }
        break;
    }
    case DLL_PROCESS_DETACH:

        break;
    }
    return TRUE;
}

