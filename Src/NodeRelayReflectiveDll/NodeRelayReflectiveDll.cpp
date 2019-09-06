#include "StdAfx.h"

// Reflective-Dll-related stuff.
#include "GlobalInjectedData.hpp"
namespace MWR::C3::ReflectiveDll { DEFINE_INJECTED_GLOBAL_SINGLETON }

/// Used both by VEH and SetUnhandledExceptionFilter. Based on BlackBone memory injection toolkit.
/// @param exceptionInfo filled _EXCEPTION_POINTERS structure describing occurred exception.
/// @return always returns EXCEPTION_CONTINUE_SEARCH.
LONG CALLBACK GlobalExceptionHandler(PEXCEPTION_POINTERS exceptionInfo)
{
	// Filter by Visual Studio magic for C++ exception, see https://support.microsoft.com/en-us/help/185294/prb-exception-code-0xe06d7363-when-calling-win32-seh-apis.
	if (exceptionInfo->ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER and
		exceptionInfo->ExceptionRecord->ExceptionInformation[2] >= MWR::C3::ReflectiveDll::GetInjectedGlobalSingleton().m_DllBaseAddress and					// Check exception site image boundaries.
		exceptionInfo->ExceptionRecord->ExceptionInformation[2] <= MWR::C3::ReflectiveDll::GetInjectedGlobalSingleton().m_DllBaseAddress + MWR::C3::ReflectiveDll::GetInjectedGlobalSingleton().m_SizeOfTheDll and
		exceptionInfo->ExceptionRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER1 and exceptionInfo->ExceptionRecord->ExceptionInformation[3] == 0)
		{
			exceptionInfo->ExceptionRecord->ExceptionInformation[0] = (ULONG_PTR)EH_MAGIC_NUMBER1;					//< CRT magic number, used in exception records for native or mixed C++ thrown objects.
			exceptionInfo->ExceptionRecord->ExceptionInformation[3] = (ULONG_PTR)MWR::C3::ReflectiveDll::GetInjectedGlobalSingleton().m_DllBaseAddress;		//< Fix exception image base.
		}

	// Continue the handler search.
	return EXCEPTION_CONTINUE_SEARCH;
}

/// The entry point.
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID)
{
	// Proceed only if we are being attached to a process.
	if (DLL_PROCESS_ATTACH != reason)
		return TRUE;

	// Fix our exception mechanism - install VEH and UEF.
	AddVectoredExceptionHandler(0, GlobalExceptionHandler);
	SetUnhandledExceptionFilter(GlobalExceptionHandler);

	try
	{
		// Start a NodeRelay.
		MWR::C3::Utils::CreateNodeRelayFromImagePatch(
			[](MWR::C3::LogMessage const&, std::string_view*) {},
			MWR::C3::InterfaceFactory::Instance(),
			EmbeddedData::Instance()[0],
			EmbeddedData::Instance()[1],
			EmbeddedData::Instance()[2],
			EmbeddedData::Instance().FindMatching(3));
	}
	catch (...)
	{
	}

	// Indicate successful load of the library.
	return TRUE;
}
