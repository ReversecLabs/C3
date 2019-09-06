#pragma once

#include <iostream>																										//< For std::cout, std::cerr. Remove when common files will not nead it.

// C3 inclusion.
#include "Common/MWR/C3/Sdk.hpp"																						//< C3 Sdk.

// Standard library and platform includes.
#include <Ehdata.h>																										//< For VEH constants: EH_MAGIC_NUMBER1, EH_PURE_MAGIC_NUMBER1, EH_EXCEPTION_NUMBER.
#include <intrin.h>																										//< For _ReturnAddress().

// CppCommons.
#include "Common/MWR/CppTools/Payload.h"

using EmbeddedData = MWR::Payload<4096>;
