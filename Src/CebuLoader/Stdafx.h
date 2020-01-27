#pragma once

#define _HAS_EXCEPTIONS 0

// Standard library includes.
#include <iostream>																										//< For std::cout, std::cerr. Remove when common files will not nead it.
#include <algorithm>
#include <ciso646>
#include <string>
#include <csetjmp>

// Custom includes
#include "WindowsVersion.h"
#include "QuietAbort.h"
#include "PeUtils.h"
#include "UnexportedWinApi.h"

// C3 includes
//#include "Common/MWR/CppTools/ByteConverter.h"

// Windows includes
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <Ehdata.h>																										//< For VEH constants: EH_MAGIC_NUMBER1, EH_PURE_MAGIC_NUMBER1, EH_EXCEPTION_NUMBER.
#include <intrin.h>																										//< For _ReturnAddress().
#include <winnt.h>
