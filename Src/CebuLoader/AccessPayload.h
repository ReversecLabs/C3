#pragma once
#include "EmbeddedResource.h"
#ifndef EMBEDDED_DLL_PAYLOAD
#error Unknown resource guid.
#endif // !EMBEDDED_DLL_PAYLOAD

// Payload form [16 byte guid][1 byte terminator 0xff][4 byte size][body][4 byte size][ExportName (null terminated)]

/// Find start of embedded resource
/// @param startOfImage -
inline char* FindStartOfResource(void* startofImage)
{
	// Don't use size of image to limit the search to prevent incorrect boundaries searching even if image headers have been wiped
	__try
	{
		for (char* p = (char*) startofImage;; ++p)
			if (!memcmp(p, EMBEDDED_DLL_PAYLOAD, 16) && p[16] == '\xff')
				return p;
	}
	__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
	}

	return NULL;
}

/// Get size of payload (first embedded data)
/// @param start of embedded resource
/// @returns size of payload
inline size_t GetPayloadSize(void* startOfResource)
{
	return *((int32_t*)((char*) startOfResource + 17)); // 16 bytes guid, 0xff terminator
}

/// Get payload data
/// @param start of embedded resource
/// @returns pointer to beginning of payload
inline char* GetPayload(void* startOfResource)
{
	return (char*) startOfResource + 21; //16 bytes guid, 0xff terminator, four bytes size.
}

/// Get pointer past payload
/// @param start of embedded resource
/// @returns pointer past payload end
inline void* GetPayloadEnd(void* startOfResource)
{
	return GetPayload(startOfResource) + GetPayloadSize(startOfResource);
}

/// Get size of export name buffer (second embedded data)
/// @param start of embedded resource
inline size_t GetExportNameSize(void* startOfResource)
{
	return *(int32_t*)(GetPayloadEnd(startOfResource));
}

/// Get export name buffer(second embedded data)
/// @param start of embedded resource
/// @returns Exported function name (null terminated)
inline const char* GetExportName(void* startOfResource)
{
	return (char*)GetPayloadEnd(startOfResource) + 4; // this buffer's size - 4 bytes
}
