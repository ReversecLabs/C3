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
	HostInfo::HostInfo() : m_OsVersionInfo{ sizeof m_OsVersionInfo }
	{
		// Reserve buffers for winapi calls.
		DWORD computerNameBufferLength = MAX_COMPUTERNAME_LENGTH + 1, userNameBufferLength = UNLEN + 1;
		m_ComputerName.resize(computerNameBufferLength);
		m_UserName.resize(userNameBufferLength);

		// Get name of the computer.
		if (::GetComputerNameA(m_ComputerName.data(), &computerNameBufferLength))
			m_ComputerName.resize(computerNameBufferLength);
		else
			m_ComputerName.resize(0);

		// Get the user name.
		if (::GetUserNameA(m_UserName.data(), &userNameBufferLength))
			m_UserName.resize(userNameBufferLength - 1);
		else
			m_UserName.resize(0);

		using fnRtlGetVersion = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOEXW lpVersionInformation);
		auto RtlGetVersion = (fnRtlGetVersion)GetProcAddress(GetModuleHandleW(OBF_W(L"ntdll.dll")), OBF("RtlGetVersion"));
		if (RtlGetVersion)
		{
			RtlGetVersion(&m_OsVersionInfo);
		}

		m_ProcessId = ::GetCurrentProcessId();

		m_IsElevated = IsElevated();

		LPWSTR buf = nullptr;
		if (NETSETUP_JOIN_STATUS status; NERR_Success == ::NetGetJoinInformation(nullptr, &buf, &status))
		{
			SCOPE_GUARD( ::NetApiBufferFree(buf); );
			if(status == NetSetupDomainName)
				m_Domain = WidestringToString(buf);
		}
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
