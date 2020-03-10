#pragma once

#include "PrecompiledHeader.hpp"																						//< C3 Precompiled headers (if they weren't included in StdAfx.h)
#include "Internals/BackendCommons.h"																					//< C3 back-back-end and C3 front-back-end common types and functions.
#include "Internals/AutomaticRegistrator.h"																				//< For auto registering Interface factories.

// C3 Core static library.
#ifdef _WIN64
#	ifdef _DEBUG
#		pragma comment(lib, C3_BIN_DIR "Core_d64.lib")
#	elif defined(C3_RWDI)
#		pragma comment(lib, C3_BIN_DIR "Core_rwdi64.lib")
#	else
#		pragma comment(lib, C3_BIN_DIR "Core_r64.lib")
#	endif
#else
#	ifdef _DEBUG
#		pragma comment(lib, C3_BIN_DIR "Core_d86.lib")
#	elif defined(C3_RWDI)
#		pragma comment(lib, C3_BIN_DIR "Core_rwdi86.lib")
#	else
#		pragma comment(lib, C3_BIN_DIR "Core_r86.lib")
#	endif
#endif
