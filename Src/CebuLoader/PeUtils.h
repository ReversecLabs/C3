#pragma once

namespace MWR::Loader
{
	template<typename T, typename V, typename U>
	T Rva2Va(V base, U rva)
	{
		return reinterpret_cast<T>(reinterpret_cast<ULONG_PTR&>(base) + rva);
	}

	PIMAGE_DOS_HEADER GetDosHeader(UINT_PTR baseAddress);

	PIMAGE_NT_HEADERS GetNtHeaders(UINT_PTR baseAddress);

	/// Get size of image from NT headers
	/// @param baseAddress - base address of PE file image
	/// @returns size of image specified image
	DWORD GetSizeOfImage(UINT_PTR baseAddress);

	std::pair<void*, void*> GetSectionRange(void* dllBase, std::string const& sectionName);

	static inline size_t AlignValueUp(size_t value, size_t alignment)
	{
		return (value + alignment - 1) & ~(alignment - 1);
	}
}

