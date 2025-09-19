#pragma once

#include <Windows.h>

typedef struct _LSA_UNICODE_STRING { USHORT Length;	USHORT MaximumLength; PWSTR  Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, * PCLIENT_ID;

// NtAllocateVirtualMemory
EXTERN_C NTSTATUS NtAllocateVirtualMemoryWin10(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS NtAllocateVirtualMemoryWin7(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS NtAllocateVirtualMemoryWin80(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS NtAllocateVirtualMemoryWin81(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

// NtCreateThreadEx 
EXTERN_C NTSTATUS NtCreateThreadExWin10_1507(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin10_1511(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin10_1607(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin10_1703(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin10_1709(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin10_1803(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin10_1809(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin10_1903_1909(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin10_2004(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin7(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin80(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS NtCreateThreadExWin81(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

// NtProtectVirtualMemory
EXTERN_C NTSTATUS NtProtectVirtualMemoryWin10(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
EXTERN_C NTSTATUS NtProtectVirtualMemoryWin7(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
EXTERN_C NTSTATUS NtProtectVirtualMemoryWin80(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
EXTERN_C NTSTATUS NtProtectVirtualMemoryWin81(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

NTSTATUS(*NtCreateThreadEx)(
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID lpStartAddress,
	PVOID lpParameter,
	ULONG Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID lpBytesBuffer
	);

NTSTATUS(*NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

NTSTATUS(*NtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect
	);

BOOL resolveApis()
{

	DWORD buildNumber = 0;
	NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);
	OSVERSIONINFOEXW osInfo;

	*(FARPROC*)& RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

	if (NULL != RtlGetVersion) {
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		RtlGetVersion(&osInfo);
		buildNumber = osInfo.dwBuildNumber;
	}

	//Windows 10 versions have a number of APIs with which the syscall doesn't change
	//Map them here and resolve the other syscalls in the switch statement below.
	if (buildNumber >= 10240)
	{
		NtProtectVirtualMemory = &NtProtectVirtualMemoryWin10;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemoryWin10;
	}

	switch (buildNumber) {
	case 7600: //Win7
	case 7601:
		NtProtectVirtualMemory = &NtProtectVirtualMemoryWin7;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemoryWin7;
		NtCreateThreadEx = &NtCreateThreadExWin7;
		break;
	case 9200: //Win8.0
		NtProtectVirtualMemory = &NtProtectVirtualMemoryWin80;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemoryWin80;
		NtCreateThreadEx = &NtCreateThreadExWin80;
		break;
	case 9600: //Win8.1
		NtProtectVirtualMemory = &NtProtectVirtualMemoryWin81;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemoryWin81;
		NtCreateThreadEx = &NtCreateThreadExWin81;
		break;

	case 10240:
		NtCreateThreadEx = &NtCreateThreadExWin10_1507;
		break;
	case 10586:
		NtCreateThreadEx = &NtCreateThreadExWin10_1511;
		break;
	case 14393:
		NtCreateThreadEx = &NtCreateThreadExWin10_1607;
		break;
	case 15063:
		NtCreateThreadEx = &NtCreateThreadExWin10_1703;
		break;
	case 16299:
		NtCreateThreadEx = &NtCreateThreadExWin10_1709;
		break;
	case 17134:
		NtCreateThreadEx = &NtCreateThreadExWin10_1803;
		break;
	case 17763:
		NtCreateThreadEx = &NtCreateThreadExWin10_1809;
		break;
	case 18362: //Win10 1903 and 1909
	case 18363:
		NtCreateThreadEx = &NtCreateThreadExWin10_1903_1909;
		break;
	case 19041:
		NtCreateThreadEx = &NtCreateThreadExWin10_2004;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

