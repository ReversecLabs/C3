#pragma once

namespace MWR::Loader
{
	/// type of function that can be called by LoadPe
	typedef void (*ExportFunc)(void);

	/// Load PE file image and call
	/// @param dllData - pointer to PE file in memory
	/// @param callExport - name of an exported function to call. Function must have a signature of ExportFunc [typedef void (*ExportFunc)(void)]
	int LoadPe(void* dllData, std::string_view callExport);
}
