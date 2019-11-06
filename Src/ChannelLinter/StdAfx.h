#pragma once

/// Compile C3 channel tester as Gateway (Include interface metadata)
#define C3_IS_GATEWAY

// Standard library includes.
#include <iostream>
#include <optional>
#include <string_view>
#include <charconv>

// C3 inclusion.
#include "Common/MWR/C3/Sdk.hpp"
#include "Common/C3_BUILD_VERSION_HASH_PART.hxx"

using json = nlohmann::json;

#include "Common/CppCodec/base64_default_rfc4648.hpp"

#include "AppConfig.h"
#include "InputVector.h"
#include "FormElement.hpp"
#include "Form.h"
#include "MockDeviceBridge.h"
