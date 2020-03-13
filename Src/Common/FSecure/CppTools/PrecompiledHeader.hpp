#pragma once

// Standard library includes.
#include <array>																										//< For std::array.
#include <vector>																										//< For std::vector.
#include <string>																										//< For std::string.
#include <string_view>																									//< For std::string_view.
#include <functional>																									//< For std::function.
#include <filesystem>																									//< For std::filesystem::path.
#include <mutex>																										//< For std::mutex.
#include <algorithm>																									//< For std:find, std:find_if, etc.
#include <iso646.h>																										//< For alternative logical operators tokens.
#include <random>																										//< For random values.

#include "Common/ADVobfuscator/MetaString.h"

#define BYTEVECTOR_ZERO_MEMORY_DESTRUCTION																				//< Increase OpSec by clearing memory when ByteVector is destructed.
#include "ByteConverter/ByteConverter.h"																				//< For ByteView, ByteVector and ByteConverter specializations for common types.
#include "Utils.h"																										//< For common templates and helpers



// Literals.
using namespace std::string_literals;																					//< For string literals.
using namespace std::string_view_literals;																				//< For string_view literals.
using namespace FSecure::Literals;																						//< For _b and _bv.
