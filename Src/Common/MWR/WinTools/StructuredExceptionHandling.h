#pragma once

namespace MWR::WinTools::StructuredExceptionHandling
{
	/// Code pointer alias
	using CodePointer = void(*)();

	/// Dummy filter.
	/// @returns EXCEPTION_EXECUTE_HANDLER.
	int Filter(unsigned int code, struct _EXCEPTION_POINTERS* ep);

	/// Wrap call to function in empty SEH handler.
	/// @param pointer to code.
	/// @returns 0.
	DWORD WINAPI SehWrapper(CodePointer func);

	/// Arguments to be passed to RuntimeV4Host
	typedef struct gruntArgs { std::function<void(PBYTE, size_t)> func;	PBYTE gruntStager;	size_t len; }GRUNTARGS, * PGRUNTARGS;

	/// Covenant specific SEH Wrapper
	/// @param args a struct containing the arguments for the execution of an SMB grunt in memory.
	/// @returns 0
	DWORD WINAPI SehWrapperCov(PGRUNTARGS args);

	/// Wrap call in SEH handler
	/// @param func - function to call
	/// @param closure - handler called when func throws SE
	void SehWrapper(std::function<void()> const& func, std::function<void()> const& closure);
}

namespace MWR::WinTools
{
	namespace SEH = StructuredExceptionHandling;
}

