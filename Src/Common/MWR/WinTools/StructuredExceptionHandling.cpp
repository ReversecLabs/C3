#include "StdAfx.h"
#include "StructuredExceptionHandling.h"


int MWR::WinTools::StructuredExceptionHandling::Filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
	return EXCEPTION_EXECUTE_HANDLER;
}

DWORD WINAPI MWR::WinTools::StructuredExceptionHandling::SehWrapper(CodePointer func)
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

DWORD WINAPI MWR::WinTools::StructuredExceptionHandling::SehWrapperCov(PGRUNTARGS args)
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

void MWR::WinTools::StructuredExceptionHandling::SehWrapper(std::function<void()> const& func, std::function<void()> const& closure)
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

