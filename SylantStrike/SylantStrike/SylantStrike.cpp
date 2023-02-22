// SylantStrike.cpp : Hooked API implementations
//

#include "pch.h"
#include "framework.h"
#include "SylantStrike.h"

// Pointer to the trampoline function used to call the original API

pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory = nullptr;
pNtWriteVirtualMemory pOriginalNtWriteVirtualMemory = nullptr;
pNtProtectVirtualMemory pOriginalNtProtectVirtualMemory = nullptr;
pNtCreateThreadEx pOriginalNtCreateThreadEx = nullptr;
HANDLE suspiciousHandle = nullptr;
PVOID suspiciousBaseAddress = nullptr;

DWORD(NTAPI NtAllocateVirtualMemory)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect) {

	if (Protect == PAGE_EXECUTE_READWRITE && ZeroBits == (ULONG_PTR)0) {

		MessageBox(nullptr, TEXT("Malicious NtAllocateVirtualMemory usage detected! But I will allow it!"), TEXT("SylantStrike"), MB_OK);
		suspiciousHandle = ProcessHandle;
	}

	// False positive, call the original function as normal
	return pOriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

DWORD(NTAPI NtWriteVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferSize, OUT PULONG NumberOfBytesWritten)
{
	if (ProcessHandle == suspiciousHandle) {

		MessageBox(nullptr, TEXT("Malicious NtWriteVirtualMemory usage detected! But I will allow it!"), TEXT("SylantStrike"), MB_OK);
		suspiciousBaseAddress = BaseAddress;
	}

	// False positive, call the original function as normal
	return pOriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

DWORD NTAPI NtProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PULONG NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection) {

	if (NewAccessProtection == PAGE_EXECUTE_READ) {
		
		MessageBox(nullptr, TEXT("Malicious NtProtectVirtualMemory usage detected! But I will allow it!"), TEXT("SylantStrike"), MB_OK);
		suspiciousHandle = ProcessHandle;
	}

	// False positive, call the original function as normal
	return pOriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

DWORD NTAPI NtCreateThreadEx(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer)
{
	if (lpStartAddress == (LPTHREAD_START_ROUTINE)suspiciousBaseAddress) {

		MessageBox(nullptr, TEXT("Malicious NtCreateThreadEx usage detected! Aborting!"), TEXT("SylantStrike"), MB_OK);
		TerminateProcess(GetCurrentProcess(), 0xdead1337);
		return 0;
	}

	// False positive, call the original function as normal
	return pOriginalNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
}


