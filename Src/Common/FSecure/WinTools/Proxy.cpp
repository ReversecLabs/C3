#include "StdAfx.h"
#include "Proxy.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::wstring FSecure::WinTools::GetProxyConfiguration()
{
	wchar_t* pValue = nullptr;
	size_t len = 0;
	auto err = _wdupenv_s(&pValue, &len, OBF_W(L"http_proxy"));
	std::unique_ptr<wchar_t, void(*)(wchar_t*)> holder(pValue, [](wchar_t* p) { free(p); });
	return (!err && pValue && len) ? std::wstring{ pValue, len - 1 } : std::wstring{};
}
