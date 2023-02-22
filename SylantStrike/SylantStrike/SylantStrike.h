// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the CYLANTSTRIKE_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// CYLANTSTRIKE_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef CYLANTSTRIKE_EXPORTS
#define CYLANTSTRIKE_API __declspec(dllexport)
#else
#define CYLANTSTRIKE_API __declspec(dllimport)
#endif

typedef DWORD (NTAPI *pNtAllocateVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);

extern pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory;

DWORD NTAPI NtAllocateVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);

//

typedef DWORD (NTAPI *pNtWriteVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferSize, OUT PULONG NumberOfBytesWritten);

extern pNtWriteVirtualMemory pOriginalNtWriteVirtualMemory;

DWORD NTAPI NtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferSize, OUT PULONG NumberOfBytesWritten);

//

typedef DWORD (NTAPI *pNtProtectVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PULONG NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);

extern pNtProtectVirtualMemory pOriginalNtProtectVirtualMemory;

DWORD NTAPI NtProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PULONG NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);

//

typedef DWORD(NTAPI *pNtCreateThreadEx)(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);

extern pNtCreateThreadEx pOriginalNtCreateThreadEx;

DWORD NTAPI NtCreateThreadEx(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);