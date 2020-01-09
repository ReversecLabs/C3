#pragma once
#include "gen/EmbeddedResource.h"
#ifndef EMBEDDED_DLL_PAYLOAD
#error Unknown resource guid.
#endif // !EMBEDDED_DLL_PAYLOAD

// Payload form [16 byte guid][1 byte terminator 0xff][4 byte size][body][4 byte size][ExportName (null terminated)]

static char* FindStartOfResource(void* startofImage)
{
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

static size_t GetPayloadSize(void* startOfResource)
{
	return *((int32_t*)((char*) startOfResource + 17)); // 16 bytes guid, 0xff terminator
}

static char* GetPayload(void* startOfResource)
{
	return (char*) startOfResource + 21; //16 bytes guid, 0xff terminator, four bytes size.
}

inline void* GetPayloadEnd(void* startOfResource)
{
	return GetPayload(startOfResource) + GetPayloadSize(startOfResource);
}

inline size_t GetExportNameSize(void* startOfResource)
{
	return *(int32_t*)(GetPayloadEnd(startOfResource));
}

inline const char* GetExportName(void* startOfResource)
{
	return (char*)GetPayloadEnd(startOfResource) + 4;
}