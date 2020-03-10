#pragma once

// Windows includes.
#ifndef NOMINMAX
#	define NOMINMAX																										//< Exclude min and max macros from windows.h.
#endif
#define WIN32_LEAN_AND_MEAN																								//< Exclude rarely-used stuff from Windows headers.
#include <windows.h>
#include "Proxy.h"
#include "StructuredExceptionHandling.h"
#include "HostInfo.h"
#include "InjectionBuffer.h"
