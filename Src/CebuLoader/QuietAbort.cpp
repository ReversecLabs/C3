#include "stdafx.h"
#include "QuietAbort.h"

namespace MWR::Loader
{
	std::jmp_buf g_JmpBuf;

	[[noreturn]] void QuietAbort()
	{
		std::longjmp(g_JmpBuf, 1);
	}
}
