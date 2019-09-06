//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice, this list of
// conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice, this list of
// conditions and the following disclaimer in the documentation and/or other materials provided
// with the distribution.
//
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "StdAfx.h"
#include "ReflectiveLoader.h"
#include "../GlobalInjectedData.hpp"

//===============================================================================================//
// ADD: For C++ exception handling support
// Based on BlackBone memory injection toolkit
/*
LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	// Check if it's a VC++ exception
	// for SEH RtlAddFunctionTable is enough
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER)
	{
		printf("gDLLBaseAddress: %Iu \n", gDLLBaseAddress);
		printf("gDLLSize: %lu \n", gDLLSize);
		printf("ExceptionInfo->ExceptionRecord->ExceptionInformation[2]: %Iu \n", ExceptionInfo->ExceptionRecord->ExceptionInformation[2]);

		// Check exception site image boundaries
		if (ExceptionInfo->ExceptionRecord->ExceptionInformation[2] >= gDLLBaseAddress &&
			ExceptionInfo->ExceptionRecord->ExceptionInformation[2] <= gDLLBaseAddress + gDLLSize)
		{
			// Assume that's our exception because ImageBase = 0 and not suitable magic number
			if (ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER1
				&& ExceptionInfo->ExceptionRecord->ExceptionInformation[3] == 0)
			{
				// CRT magic number
				ExceptionInfo->ExceptionRecord->ExceptionInformation[0] = (ULONG_PTR)EH_MAGIC_NUMBER1;

				// fix exception image base
				ExceptionInfo->ExceptionRecord->ExceptionInformation[3] = (ULONG_PTR)gDLLBaseAddress;
				printf("\n\nDONE\n\n");

			}
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}
*/

//===============================================================================================//
// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;
//===============================================================================================//
//#pragma intrinsic( _ReturnAddress )											//< Visual Studio: warning C4164: '_ReturnAddress': intrinsic function not declared.
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller(VOID) {
	return (ULONG_PTR)_ReturnAddress(); DebugBreak();
}

//===============================================================================================//

// Note 1: If you want to have your own DllMain, define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN,
//         otherwise the DllMain at the end of this file will be used.

// Note 2: If you are injecting the DLL via LoadRemoteLibraryR, define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR,
//         otherwise it is assumed you are calling the ReflectiveLoader via a stub.





// This is our position independent reflective DLL loader/injector
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
#else
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID)
#endif
{
	// the functions we need
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;
	RTLADDFUNCTIONTABLE pRtlAddFunctionTable = NULL; // ADD
	RTLINSTALLFUNCTIONTABLECALLBACK pRtlInstallFunctionTableCallback = NULL; // ADD
	WRITEPROCESSMEMORY pWriteProcessMemory = NULL; // ADD
	RTLADDVECTOREDEXCEPTIONHANDLER pRtlAddVectoredExceptionHandler = NULL; // ADD
	ADDVECTOREDEXCEPTIONHANDLER pAddVectoredExceptionHandler = NULL; // ADD

	USHORT usCounter;

	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

	// STEP 0: calculate our images current base address

	// we will start searching backwards from our callers return address.
	uiLibraryAddress = caller();

	// loop through memory backwards searching for our images base address
	// we dont need SEH style search as we shouldnt generate any access violations with this
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
			{
				uiHeaderValue += uiLibraryAddress;
				// break if we have found a valid MZ/PE header
				if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		uiLibraryAddress--;
	}

	// STEP 1: process the kernels exports for the functions our loader needs...

	// get the Process Enviroment Block
#ifdef WIN_X64
	uiBaseAddress = __readgsqword(0x60);
#else
#ifdef WIN_X86
	uiBaseAddress = __readfsdword(0x30);
#endif
#endif

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

	// get the first entry of the InMemoryOrder module list
	uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
	while (uiValueA)
	{
		// get pointer to current modules name (unicode string)
		uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		uiValueC = 0;

		// compute the hash of the module name...
		do
		{
			uiValueC = ror((DWORD)uiValueC);
			// normalize to uppercase if the madule name is in lowercase
			if (*((BYTE *)uiValueB) >= 'a')
				uiValueC += *((BYTE *)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE *)uiValueB);
			uiValueB++;
		} while (--usCounter);

		// compare the hash with that of kernel32.dll
		if ((DWORD)uiValueC == KERNEL32DLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

			usCounter = 6; // ADD (mod to 6)

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH ||
					dwHashValue == VIRTUALALLOC_HASH || dwHashValue == RTLADDFUNCTIONTABLE_HASH || // ADD
					dwHashValue == RTLINSTALLFUNCTIONTABLECALLBACK_HASH || dwHashValue == ADDVECTOREDEXCEPTIONHANDLER_HASH) // ADD   //// REMOVED: || dwHashValue == WRITEPROCESSMEMORY_HASH
				{
					// get the VA for the array of addresses
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (dwHashValue == LOADLIBRARYA_HASH)
						pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == GETPROCADDRESS_HASH)
						pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == VIRTUALALLOC_HASH)
						pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == RTLADDFUNCTIONTABLE_HASH) // ADD
						pRtlAddFunctionTable = (RTLADDFUNCTIONTABLE)(uiBaseAddress + DEREF_32(uiAddressArray)); // ADD
					else if (dwHashValue == RTLINSTALLFUNCTIONTABLECALLBACK_HASH) // ADD
						pRtlInstallFunctionTableCallback = (RTLINSTALLFUNCTIONTABLECALLBACK)(uiBaseAddress + DEREF_32(uiAddressArray)); // ADD
					else if (dwHashValue == ADDVECTOREDEXCEPTIONHANDLER_HASH) // ADD
						pAddVectoredExceptionHandler = (ADDVECTOREDEXCEPTIONHANDLER)(uiBaseAddress + DEREF_32(uiAddressArray)); // ADD

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}
		else if ((DWORD)uiValueC == NTDLLDLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

			usCounter = 2; // ADD (mod to 2)

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH || dwHashValue == RTLADDVECTOREDEXCEPTIONHANDLER_HASH)
				{
					// get the VA for the array of addresses
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
						pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == RTLADDVECTOREDEXCEPTIONHANDLER_HASH) // ADD
						pRtlAddVectoredExceptionHandler = (RTLADDVECTOREDEXCEPTIONHANDLER)(uiBaseAddress + DEREF_32(uiAddressArray)); // ADD

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}

		// we stop searching when we have found everything we need.
		if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache && pRtlAddFunctionTable && // ADD
			pRtlInstallFunctionTableCallback && pRtlAddVectoredExceptionHandler && pAddVectoredExceptionHandler) // ADD
			break;

		// get the next entry
		uiValueA = DEREF(uiValueA);
	}

	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	while (uiValueA--)
		*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

	// STEP 3: load in all of our sections...

	// uiValueA = the VA of the first section
	uiValueA = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		// uiValueB is the VA for this section
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// uiValueC if the VA for this sections data
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		while (uiValueD--)
			*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

		// get the VA of the next section
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// itterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = (uiBaseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// STEP 5: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}

#if _WIN64

	// STEP 5b: Set up Structured Exception Handling (SEH)
	PIMAGE_DATA_DIRECTORY pImageEntryException = &((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (pImageEntryException->Size > 0)
	{
		(ULONG_PTR)pRtlAddFunctionTable((PRUNTIME_FUNCTION)(uiBaseAddress + pImageEntryException->VirtualAddress),
			pImageEntryException->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)uiBaseAddress);
	}

	//// Part B: Set up VEH
	//ULONG_PTR pModTable = (ULONG_PTR)pVirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	//struct ExceptionModule
	//{
	//	uint64_t base;
	//	uint64_t size;
	//};

	//struct ModuleTable
	//{
	//	uint64_t count;                    // Number of used entries
	//	ExceptionModule entry[250];     // Module data
	//};

	//ModuleTable table;
	//table.entry[table.count].base = uiBaseAddress; // Possible issue? Not the entry point: uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint
	//table.entry[table.count].size = (((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage * 10);
	//table.count++;
	//memcpy(&pModTable, &table, sizeof(ModuleTable));

	//ULONG_PTR pVEHCode = (ULONG_PTR)pVirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//auto replaceStub = [](uint8_t* ptr, size_t size, auto oldVal, auto newVal)
	//{
	//	using ValuePtr = std::add_pointer_t<decltype(oldVal)>;

	//	for (uint8_t *pData = ptr; pData < ptr + size - sizeof(oldVal); pData++)
	//	{
	//		if (*reinterpret_cast<ValuePtr>(pData) == oldVal)
	//		{
	//			*reinterpret_cast<ValuePtr>(pData) = newVal;
	//			return true;
	//		}
	//	}

	//	return false;
	//};

	///*
	//LONG CALLBACK VectoredHandler( PEXCEPTION_POINTERS ExceptionInfo )
	//{
	//	// Check if it's a VC++ exception
	//	// for SEH RtlAddFunctionTable is enough
	//	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER)
	//	{
	//		ModuleTable* pTable = reinterpret_cast<ModuleTable*>(0xDEADBEEFDEADBEEF);
	//		for (ptr_t i = 0; i < pTable->count; i++)
	//		{
	//			// Check exception site image boundaries
	//			if (ExceptionInfo->ExceptionRecord->ExceptionInformation[2] >= pTable->entry[i].base &&
	//				ExceptionInfo->ExceptionRecord->ExceptionInformation[2] <= pTable->entry[i].base + pTable->entry[i].size)
	//			{
	//				// Assume that's our exception because ImageBase = 0 and not suitable magic number
	//				if (ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER1
	//					&& ExceptionInfo->ExceptionRecord->ExceptionInformation[3] == 0)
	//				{
	//					// CRT magic number
	//					ExceptionInfo->ExceptionRecord->ExceptionInformation[0] = (ULONG_PTR)EH_MAGIC_NUMBER1;

	//					// fix exception image base
	//					ExceptionInfo->ExceptionRecord->ExceptionInformation[3] = (ULONG_PTR)pTable->entry[i].base;
	//				}
	//			}
	//		}
	//	}

	//	return EXCEPTION_CONTINUE_SEARCH;
	//}*/
	//uint8_t _handler64[] =
	//{
	//	0x48, 0x83, 0xEC, 0x08, 0x48, 0x8B, 0x01, 0x4C, 0x8B, 0xD9, 0x81, 0x38, 0x63, 0x73, 0x6D, 0xE0,
	//	0x0F, 0x85, 0x7C, 0x00, 0x00, 0x00, 0x48, 0x89, 0x1C, 0x24, 0x45, 0x33, 0xC9, 0x48, 0xBB, 0xEF,
	//	0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x4C, 0x39, 0x0B, 0x76, 0x5B, 0x48, 0xB8, 0xF7, 0xBE,
	//	0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	//	0x4D, 0x8B, 0x03, 0x48, 0x8B, 0x10, 0x4D, 0x8B, 0x50, 0x30, 0x4C, 0x3B, 0xD2, 0x72, 0x2C, 0x48,
	//	0x03, 0x50, 0x08, 0x4C, 0x3B, 0xD2, 0x77, 0x23, 0x49, 0x81, 0x78, 0x20, 0x00, 0x40, 0x99, 0x01,
	//	0x75, 0x19, 0x49, 0x83, 0x78, 0x38, 0x00, 0x75, 0x12, 0x49, 0xC7, 0x40, 0x20, 0x20, 0x05, 0x93,
	//	0x19, 0x49, 0x8B, 0x13, 0x48, 0x8B, 0x08, 0x48, 0x89, 0x4A, 0x38, 0x49, 0xFF, 0xC1, 0x48, 0x83,
	//	0xC0, 0x10, 0x4C, 0x3B, 0x0B, 0x72, 0xB9, 0x33, 0xC0, 0x48, 0x8B, 0x1C, 0x24, 0x48, 0x83, 0xC4,
	//	0x08, 0xC3, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x08, 0xC3
	//};

	//uint8_t newHandler[sizeof(_handler64)];
	//size_t handlerSize = 0;

	//handlerSize = sizeof(_handler64);
	//memcpy(newHandler, _handler64, handlerSize);

	//// Slight modification to confirm success
	//if (!replaceStub(newHandler, handlerSize, 0xDEADBEEFDEADBEEF, pModTable))
	//	exit(1);
	//if(!replaceStub(newHandler, handlerSize, 0xDEADBEEFDEADBEF7, pModTable + sizeof(uint64_t)))
	//	exit(1);
	//
	//memcpy(&pVEHCode, &newHandler, sizeof(newHandler));

	//// TBA: RtlAddVectoredExceptionHandler
	//(ULONG_PTR)pRtlAddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)pVEHCode); //PVECTORED_EXCEPTION_HANDLER

#endif

	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// Scan the memory, find the signature and replace it with a filled GlobalInjectedData structure.
	for (char* p = (char*)uiBaseAddress; p < (char*)(uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage); ++p)
		COMPARE_SIGNATURE_TO_BYTES_AT_ADDRESS(p)
	{
		// Thanks to the way placement new mechanics works, we also don't need to worry about the automatic destructor call.
		new (p - 1) MWR::C3::ReflectiveDll::GlobalInjectedData(
			MWR::C3::ReflectiveDll::GlobalInjectedData::InjectionMethod::Stephens,
			uiBaseAddress,
			reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.SizeOfImage
		);
		break;																//< We expect that there's only one copy of the SIGNATURE in memory, no need to continue.
	}

	// call our respective entry point, fudging our hInstance value
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)

	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
	//pRtlAddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandler);
#else
	// if we are injecting an DLL via a stub we call DllMain with no parameter
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
#endif

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return uiValueA;
}
//===============================================================================================//
#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}

#endif
