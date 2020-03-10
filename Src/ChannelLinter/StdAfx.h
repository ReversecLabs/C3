#pragma once

/// Compile C3 channel tester as Gateway (Include interface metadata)
#define C3_IS_GATEWAY

// Standard library includes.
#include <iostream>
#include <optional>
#include <string_view>
#include <charconv>
#include <utility>

// C3 inclusion.
#include "Common/FSecure/C3/Sdk.hpp"
#include "Common/C3_BUILD_VERSION_HASH_PART.hxx"

using json = nlohmann::json;

#include "Common/CppCodec/base64_default_rfc4648.hpp"

#include "argparse.hpp"
#include "AppConfig.hpp"
#include "ArgumentParser.h"
#include "FormElement.h"
#include "Form.h"
#include "MockDeviceBridge.h"
#include "ChannelLinter.h"
