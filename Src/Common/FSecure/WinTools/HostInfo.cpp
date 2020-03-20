#include "StdAfx.h"
#include "HostInfo.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"
#include "Shlobj.h"
#include "Lm.h"
#include <sstream>

namespace FSecure
{
	namespace
	{
		std::string WidestringToString(std::wstring const& wstr)
		{
			if (wstr.empty())
				return {};

			int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, &wstr[0], static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
			std::string ret(size, 0);
			WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, &wstr[0], static_cast<int>(wstr.size()), &ret[0], size, NULL, NULL);
			return ret;
		}

		bool IsElevated() noexcept
		{
			HANDLE hToken = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
				return false;

			SCOPE_GUARD( CloseHandle(hToken); );
			TOKEN_ELEVATION Elevation;
			DWORD cbSize = sizeof(TOKEN_ELEVATION);
			if (!GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
				return false;

			return Elevation.TokenIsElevated;
		}
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	HostInfo HostInfo::Gather()
	{
		// Reserve buffers for winapi calls.
		DWORD computerNameBufferLength = MAX_COMPUTERNAME_LENGTH + 1, userNameBufferLength = UNLEN + 1;
		std::string computerName(computerNameBufferLength, '\0');
		std::string userName(userNameBufferLength, '\0');

		// Get name of the computer.
		if (::GetComputerNameA(computerName.data(), &computerNameBufferLength))
			computerName.resize(computerNameBufferLength);
		else
			computerName.resize(0);

		// Get the user name.
		if (::GetUserNameA(userName.data(), &userNameBufferLength))
			userName.resize(userNameBufferLength - 1);
		else
			userName.resize(0);

		RTL_OSVERSIONINFOEXW osVersionInfo{ sizeof(osVersionInfo) };
		using fnRtlGetVersion = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOEXW lpVersionInformation);
		auto RtlGetVersion = (fnRtlGetVersion)GetProcAddress(GetModuleHandleW(OBF(L"ntdll.dll")), OBF("RtlGetVersion"));
		if (RtlGetVersion)
			RtlGetVersion(&osVersionInfo);

		DWORD processId = ::GetCurrentProcessId();

		std::string domain;
		LPWSTR buf = nullptr;
		if (NETSETUP_JOIN_STATUS status; NERR_Success == ::NetGetJoinInformation(nullptr, &buf, &status))
		{
			SCOPE_GUARD( ::NetApiBufferFree(buf); );
			if(status == NetSetupDomainName)
				domain = WidestringToString(buf);
		}

		return HostInfo(std::move(computerName), std::move(userName), std::move(domain), std::move(osVersionInfo), processId, IsElevated());
	}

	HostInfo::HostInfo(std::string computerName, std::string userName, std::string domain, RTL_OSVERSIONINFOEXW osVersionInfo, DWORD processId, bool isElevated)
		: m_ComputerName{ std::move(computerName) }
		, m_UserName{ std::move(userName) }
		, m_Domain{ std::move(domain) }
		, m_OsVersionInfo{ std::move(osVersionInfo) }
		, m_ProcessId(processId)
		, m_IsElevated(isElevated)
	{
	}

	HostInfo::HostInfo(const json& json)
	{
		json.at("ComputerName").get_to(m_ComputerName);
		json.at("UserName").get_to(m_UserName);
		json.at("Domain").get_to(m_Domain);
		json.at("OsMajorVersion").get_to(m_OsVersionInfo.dwMajorVersion);
		json.at("OsMinorVersion").get_to(m_OsVersionInfo.dwMinorVersion);
		json.at("OsBuildNumber").get_to(m_OsVersionInfo.dwBuildNumber);
		json.at("OsServicePackMajor").get_to(m_OsVersionInfo.wServicePackMajor);
		json.at("OsServicePackMinor").get_to(m_OsVersionInfo.wServicePackMinor);
		json.at("OsProductType").get_to(m_OsVersionInfo.wProductType);
		json.at("ProcessId").get_to(m_ProcessId);
		json.at("IsElevated").get_to(m_IsElevated);
	}

	void to_json(json& j, const HostInfo& hi)
	{
		j = json
		{
			{"ComputerName", hi.m_ComputerName},
			{"UserName", hi.m_UserName},
			{"Domain", hi.m_Domain},
			{"ProcessId", hi.m_ProcessId},
			{"OsMajorVersion", hi.m_OsVersionInfo.dwMajorVersion},
			{"OsMinorVersion", hi.m_OsVersionInfo.dwMinorVersion},
			{"OsBuildNumber", hi.m_OsVersionInfo.dwBuildNumber},
			{"OsServicePackMajor", hi.m_OsVersionInfo.wServicePackMajor},
			{"OsServicePackMinor", hi.m_OsVersionInfo.wServicePackMinor},
			{"OsProductType", hi.m_OsVersionInfo.wProductType},
			{"IsElevated", hi.m_IsElevated},
		};
	}
}
