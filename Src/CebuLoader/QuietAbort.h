#pragma once

/// Macro to wrap code that can call QuietAbort()
/// It should be used only once per call stack
#define FSECURE_SET_QUIET_ABORT(x) if(std::setjmp(FSecure::Loader::g_JmpBuf) == 0) { x } else {}

namespace FSecure::Loader
{
	extern std::jmp_buf g_JmpBuf;

	/// Return execution just past the place where FSECURE_SET_QUIET_ABORT was used
	[[noreturn]] void QuietAbort();
}
