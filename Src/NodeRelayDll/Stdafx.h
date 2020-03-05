#pragma once

#include <iostream>																										//< For std::cout, std::cerr. Remove when common files will not nead it.

// C3 inclusion.
#include "Common/FSecure/C3/Sdk.hpp"																						//< C3 Sdk.

// CppCommons.
#include "Common/FSecure/CppTools/Payload.h"

using EmbeddedData = FSecure::Payload<4096>;
