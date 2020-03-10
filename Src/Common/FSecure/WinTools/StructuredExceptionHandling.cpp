#include "StdAfx.h"
#include "StructuredExceptionHandling.h"


int FSecure::WinTools::StructuredExceptionHandling::Filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
	return EXCEPTION_EXECUTE_HANDLER;
}

DWORD WINAPI FSecure::WinTools::StructuredExceptionHandling::SehWrapper(CodePointer func)
{
	__try
	{
		func();
	}
	__except (Filter(GetExceptionCode(), GetExceptionInformation()))
	{
		// Nothing
	}

	return 0;
}

DWORD WINAPI FSecure::WinTools::StructuredExceptionHandling::SehWrapperCov(PGRUNTARGS args)
{
	__try
	{
		//this is kind of gross but the only way I could get it to work.
		args->func(args->gruntStager, args->len);
	}
	__except (Filter(GetExceptionCode(), GetExceptionInformation()))
	{
		// Nothing
	}

	return 0;
}

void FSecure::WinTools::StructuredExceptionHandling::SehWrapper(std::function<void()> const& func, std::function<void()> const& closure)
{
	__try
	{
		func();
	}
	__except (Filter(GetExceptionCode(), GetExceptionInformation()))
	{
		closure();
	}
}

