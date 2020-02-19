#pragma once

/// Macro to wrap code that can call QuietAbort()
/// It should be used only once per call stack
#define MWR_SET_QUIET_ABORT(x) if(std::setjmp(MWR::Loader::g_JmpBuf) == 0) { x } else {}

namespace MWR::Loader
{
	extern std::jmp_buf g_JmpBuf;

	/// Return execution just past the place where MWR_SET_QUIET_ABORT was used
	[[noreturn]] void QuietAbort();
}
