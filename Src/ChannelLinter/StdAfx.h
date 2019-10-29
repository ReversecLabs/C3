#pragma once

/// Compile C3 channel tester as Gateway (Include interface metadata)
#define C3_IS_GATEWAY

// Standard library includes.
#include <iostream>
#include <optional>

// C3 inclusion.
#include "Common/MWR/C3/Sdk.hpp"
#include "Common/C3_BUILD_VERSION_HASH_PART.hxx"

using json = nlohmann::json;

#include "InputContext.h"
#include "InputVector.h"
#include "Form.h"
