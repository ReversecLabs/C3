#pragma once

namespace FSecure::Loader
{
	/// Calculate VA from base address and RVA
	/// @tparam T - type of return value
	/// @param baseAddress
	/// @param RVA
	/// @returns VA
	template<typename T, typename V, typename U>
	T Rva2Va(V baseAddress, U rva)
	{
		return reinterpret_cast<T>(reinterpret_cast<ULONG_PTR&>(baseAddress) + rva);
	}

	/// Get DOS header from dll base address
	/// @param base address of dll
	/// @returns DOS header of dll
	PIMAGE_DOS_HEADER GetDosHeader(UINT_PTR baseAddress);

	/// Get NT headers from dll base address
	/// @param base address of dll
	/// @returns NT headers of dll
	PIMAGE_NT_HEADERS GetNtHeaders(UINT_PTR baseAddress);

	/// Get size of image from NT headers
	/// @param baseAddress - base address of PE file image
	/// @returns size of image specified image
	DWORD GetSizeOfImage(UINT_PTR baseAddress);

	/// Get memory range of dll section
	/// @param dllbase - base address of dll
	/// @param section name - name of section to find
	/// @returns pair of pointers - memory range of section
	std::pair<void*, void*> GetSectionRange(void* dllBase, std::string const& sectionName);

	/// Align value up
	/// @param value to align
	/// @param alignment required, must be a power of 2
	/// @returns value aligned to requirement
	static inline size_t AlignValueUp(size_t value, size_t alignment)
	{
		return (value + alignment - 1) & ~(alignment - 1);
	}
}
