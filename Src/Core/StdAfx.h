#pragma once

// C3 Precompiled header.
#include "Common/FSecure/C3/PrecompiledHeader.hpp"

// Standard library includes.
#include <chrono>																										//< C++ time library.
#include <cctype>																										//< For std::isprint().
#include <fstream>																										//< Used by BinaryImageUtils.
#include <optional>																										//< For std::optional.
#include <type_traits>																									//< For traits.
#include <iostream>																										//< For std::cout. Parts that are common for NodeRelay and GateRelay should not use it.
#include <future>																										//< For async

// External dependencies.
#include "Common/json/json.hpp"																							//< For json.

// Namespaces.
using json = nlohmann::json;																							//< For JSON format.

// Literals.
using namespace std::chrono_literals;
