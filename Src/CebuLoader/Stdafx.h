#pragma once

// Standard library includes.
#include <iostream>																										//< For std::cout, std::cerr. Remove when common files will not nead it.
#include <algorithm>
#include <string>

#include "WindowsVersion.h"
#include "UnexportedWinApi.h"

#include <windows.h>
#include <Ehdata.h>																										//< For VEH constants: EH_MAGIC_NUMBER1, EH_PURE_MAGIC_NUMBER1, EH_EXCEPTION_NUMBER.
#include <intrin.h>																										//< For _ReturnAddress().
#include <winnt.h>