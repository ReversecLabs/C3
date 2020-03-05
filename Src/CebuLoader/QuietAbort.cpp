#include "stdafx.h"
#include "QuietAbort.h"

namespace FSecure::Loader
{
	std::jmp_buf g_JmpBuf;

	[[noreturn]] void QuietAbort()
	{
		std::longjmp(g_JmpBuf, 1);
	}
}
