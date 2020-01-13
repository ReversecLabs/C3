#include "StdAfx.h"
#include "AccessPayload.h"
#include "UnexportedWinApi.h"

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

template<typename T, typename V, typename U>
T Rva2Va(V base, U rva)
{
	return reinterpret_cast<T>((ULONG_PTR)base + rva);
}

#define RVA(type, base, rva) Rva2Va<type>(base, rva)

static inline size_t
AlignValueUp(size_t value, size_t alignment) {
	return (value + alignment - 1) & ~(alignment - 1);
}

#pragma warning( push )
#pragma warning( disable : 4214 ) // nonstandard extension
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;
#pragma warning(pop)

typedef BOOL(WINAPI* DllEntryPoint)(HINSTANCE, DWORD, LPVOID);
typedef void (*EXPORTFUNC)(void);

struct ModuleData
{
	UINT_PTR m_DllBaseAddress;
	DWORD m_SizeOfTheDll;
};

ModuleData moduleData;

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

/// Entry point of the application.
int LoadPe(void* dllData, std::string_view callExport)
{
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

	UINT_PTR baseAddress = (UINT_PTR)VirtualAlloc(NULL, alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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
		auto importDesc = RVA(PIMAGE_IMPORT_DESCRIPTOR, baseAddress, dataDir->VirtualAddress);
		auto importCount = 0;
		for (; importDesc->Name; importDesc++)
			importCount++;

		importDesc = RVA(PIMAGE_IMPORT_DESCRIPTOR, baseAddress, dataDir->VirtualAddress);
		for (; importDesc->Name; importDesc++)
		{
			auto libraryAddress = (PBYTE)LoadLibraryA((LPCSTR)(baseAddress + importDesc->Name));
			auto firstThunk = RVA(PIMAGE_THUNK_DATA, baseAddress, importDesc->FirstThunk);
			auto origFirstThunk = RVA(PIMAGE_THUNK_DATA, baseAddress, importDesc->OriginalFirstThunk);

			// iterate through all imported functions, importing by ordinal if no name present
			for (; origFirstThunk->u1.Function; firstThunk++, origFirstThunk++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(origFirstThunk->u1.Ordinal))
				{
					firstThunk->u1.Function = (ULONG_PTR)GetProcAddress((HMODULE)libraryAddress, (LPCSTR)IMAGE_ORDINAL(origFirstThunk->u1.Ordinal));
				}
				else
				{
					auto importByName = RVA(PIMAGE_IMPORT_BY_NAME, baseAddress, origFirstThunk->u1.AddressOfData);
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
		auto delayDesc = RVA(PIMAGE_DELAYLOAD_DESCRIPTOR, baseAddress, dataDir->VirtualAddress);

		for (; delayDesc->DllNameRVA; delayDesc++)
		{
			auto libraryAddress = (PBYTE)LoadLibraryA((LPCSTR)(baseAddress + delayDesc->DllNameRVA));
			auto firstThunk = RVA(PIMAGE_THUNK_DATA, baseAddress, delayDesc->ImportAddressTableRVA);
			auto origFirstThunk = RVA(PIMAGE_THUNK_DATA, baseAddress, delayDesc->ImportNameTableRVA);

			// iterate through all imported functions, importing by ordinal if no name present
			for (; firstThunk->u1.Function; firstThunk++, origFirstThunk++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(origFirstThunk->u1.Ordinal))
				{
					firstThunk->u1.Function = (ULONG_PTR)GetProcAddress((HMODULE)libraryAddress, (LPCSTR)IMAGE_ORDINAL(origFirstThunk->u1.Ordinal));
				}
				else
				{
					auto importByName = RVA(PIMAGE_IMPORT_BY_NAME, baseAddress, origFirstThunk->u1.AddressOfData);
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
			VirtualProtect(RVA(LPVOID, baseAddress, sectionHeader->VirtualAddress), sectionHeader->SizeOfRawData, protect, &protect);
		}
	}

	// We must flush the instruction cache to avoid stale code being used
	FlushInstructionCache((HANDLE)-1, nullptr, 0);

	///
	// STEP 7.1: Set static TLS values
	///

	using namespace MWR::Loader;
	{
		UnexportedWinApi::LDR_DATA_TABLE_ENTRY ldrDataTableEntry{};
		ldrDataTableEntry.DllBase = (void*)baseAddress;
		auto ldrpHandleTlsData = UnexportedWinApi::GetLdrpHandleTlsData();
		ldrpHandleTlsData(&ldrDataTableEntry);
	}
	///
	// STEP 8: execute TLS callbacks
	///
	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (dataDir->Size)
	{
		auto tlsDir = RVA(PIMAGE_TLS_DIRECTORY, baseAddress, dataDir->VirtualAddress);
		auto callback = (PIMAGE_TLS_CALLBACK*)(tlsDir->AddressOfCallBacks);

		for (; *callback; callback++)
			(*callback)((LPVOID)baseAddress, DLL_PROCESS_ATTACH, NULL);
	}

	//
	// STEP 8.1: Add Exception handling
	//
#if defined _WIN64
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

#elif defined _WIN32
	auto rtlInsertInvertedFunctionTable = UnexportedWinApi::GetRtlInsertInvertedFunctionTable();
	if (IsWindows8Point1OrGreater())
		((UnexportedWinApi::RtlInsertInvertedFunctionTableWin8Point1OrGreater)rtlInsertInvertedFunctionTable)((void*)baseAddress, ntHeaders->OptionalHeader.SizeOfImage);
	else if (IsWindows8OrGreater())
		((UnexportedWinApi::RtlInsertInvertedFunctionTableWin8OrGreater)rtlInsertInvertedFunctionTable)((void*)baseAddress, ntHeaders->OptionalHeader.SizeOfImage);
	else
		abort(); // TODO
#endif


	///
	// STEP 9: call our images entry point
	///
	auto dllEntryPoint = RVA(DllEntryPoint, baseAddress, ntHeaders->OptionalHeader.AddressOfEntryPoint);
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

			auto expName = RVA(PDWORD, baseAddress, exportDir->AddressOfNames);
			auto expOrdinal = RVA(PWORD, baseAddress, exportDir->AddressOfNameOrdinals);

			for (size_t i = 0; i < exportDir->NumberOfNames; i++, expName++, expOrdinal++)
			{
				auto expNameStr = RVA(LPCSTR, baseAddress, *expName);

				if (!expNameStr)
					break;

				if (expNameStr == callExport && expOrdinal)
				{
					auto exportFunc = RVA(EXPORTFUNC, baseAddress, *(PDWORD)(baseAddress + exportDir->AddressOfFunctions + (*expOrdinal * 4)));
					exportFunc();
					break;
				}
			}
		} while (0);
	}

	// STEP 11 Cleanup
#if defined _WIN64
	RemoveVectoredExceptionHandler(veh);
#endif
	// TODO cleanup after RtlAddFunctionTable
	VirtualFree((void*)baseAddress, alignedImageSize, MEM_RELEASE);
	return 0;
}

void ExecResource(void* baseAddress)
{
	if (auto resource = FindStartOfResource(baseAddress))
	{
		auto dllData = GetPayload(resource);
		auto exportFunc = GetExportName(resource);
		LoadPe(dllData, exportFunc);
	}
}

#ifdef NDEBUG
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
	// Indicate successful load of the library.
	if (reason == DLL_PROCESS_ATTACH)
		ExecResource(instance);

	return TRUE;
}
#else

int main()
{
	ExecResource(GetModuleHandle(NULL));
}
#endif
