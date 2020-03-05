#pragma once

// Windows includes.
#ifndef NOMINMAX
#	define NOMINMAX																										//< Exclude min and max macros from windows.h.
#endif
#define WIN32_LEAN_AND_MEAN																								//< Exclude rarely-used stuff from Windows headers.
#include <wincrypt.h>																									//< Windows cryptography.

// External dependencies.
#if !defined(SODIUM_STATIC)
#	define SODIUM_STATIC
#endif

#if !defined(SODIUM_EXPORT)
#	define SODIUM_EXPORT
#endif

#include "Common/libSodium/include/sodium.h"																			//< LibSodium.

// Static libraries.
#ifdef _WIN64
#	ifdef _DEBUG
#		pragma comment(lib, "Common/libSodium/libsodium-x64-v141-debug.lib")
#	else
#		pragma comment(lib, "Common/libSodium/libsodium-x64-v141-release.lib")
#	endif
#else
#	ifdef _DEBUG
#		pragma comment(lib, "Common/libSodium/libsodium-x86-v141-debug.lib")
#	else
#		pragma comment(lib, "Common/libSodium/libsodium-x86-v141-release.lib")
#	endif
#endif
