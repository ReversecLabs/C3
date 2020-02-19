#include "stdafx.h"
#include "PeUtils.h"

namespace MWR::Loader
{
	PIMAGE_DOS_HEADER GetDosHeader(UINT_PTR baseAddress)
	{
		return Rva2Va<PIMAGE_DOS_HEADER>(baseAddress, 0);
	}

	PIMAGE_NT_HEADERS GetNtHeaders(UINT_PTR baseAddress)
	{
		auto dosHeader = GetDosHeader(baseAddress);
		return Rva2Va<PIMAGE_NT_HEADERS>(baseAddress, dosHeader->e_lfanew);
	}

	DWORD GetSizeOfImage(UINT_PTR baseAddress)
	{
		auto ntHeaders = GetNtHeaders(baseAddress);
		return ntHeaders->OptionalHeader.SizeOfImage;
	}

	std::pair<void*, void*> GetSectionRange(void* dllBase, std::string const& sectionName)
	{
		auto ntHeaders = GetNtHeaders((UINT_PTR)dllBase);
		auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
		{
			char currentSection[9];
			memcpy(currentSection, sectionHeader->Name, 8);
			currentSection[8] = 0; // ensure null-termination
			if (_stricmp(sectionName.c_str(), currentSection) == 0)
			{
				auto sectionVa = Rva2Va<char*>(dllBase, sectionHeader->VirtualAddress);
				return { sectionVa, sectionVa + sectionHeader->Misc.VirtualSize };
			}
		}
		return {};
	}
}
