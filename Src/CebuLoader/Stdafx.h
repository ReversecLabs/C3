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
#include "LoadPe.h"

// Windows includes
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
