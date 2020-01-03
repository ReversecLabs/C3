#pragma once
#include "gen/EmbeddedResource.h"
#ifndef EMBEDDED_DLL_PAYLOAD
#error Unknown resource guid.
#endif // !EMBEDDED_DLL_PAYLOAD

// Payload form [16 byte guid][1 byte terminator 0xff][4 byte size][body]

static bool ByteCompare(char* a, char* b, size_t size)
{
	for (size_t i = 0; i < size; ++i)
		if (a[i] != b[i])
			return false;

	return true;
}

static char* FindStartOfResource(void* startofImage, size_t sizeOfImage)
{
	if (sizeOfImage >= 21)
		for (char* p = (char*) startofImage; p < (char*) startofImage + sizeOfImage - 21; ++p)
			if (ByteCompare(p, EMBEDDED_DLL_PAYLOAD, 16) && p[16] == '\xff')
				return p;

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