#pragma once

#include "Common/json/json.hpp"
#include "Common/FSecure/CppTools/ByteConverter/ByteConverter.h"


namespace FSecure
{
	using json = nlohmann::json;

	/// Holds informations about host
	struct HostInfo
	{
		std::string m_ComputerName;												///< Host name.
		std::string m_UserName;													///< Currently logged user name.
		std::string m_Domain;													///< Domain name
		OSVERSIONINFOEXA m_OsVersionInfo;										///< MS windows version info
		DWORD m_ProcessId;														///< Process Id
		bool m_IsElevated;														///< Is process run with elevated rights

		/// Gather info about host.
		HostInfo();

		/// Aggregate constructor.
		HostInfo(std::string computerName, std::string userName, std::string domain, OSVERSIONINFOEXA osVersionInfo, DWORD processId, bool isElevated);

		/// Constructor from json
		/// @param json to read from
		HostInfo(const json& json);
	};

	/// Overload ostream operator << for HostInfo
	/// @param ostream to write to
	/// @param host info to write
	std::ostream& operator <<(std::ostream& os, HostInfo const& hi);

	/// overload to_json for HostInfo
	/// @param json to write to
	/// @param host info to write
	void to_json(json& j, const HostInfo& hi);

	/// overload ByteConverter for OSVERSIONINFOEXA. szCSDVersion and wSuiteMask are omitted.
	template<>
	struct ByteConverter<OSVERSIONINFOEXA>
	{
		/// Serialize HostInfo type to ByteVector.
		/// @param obj. Object to be serialized.
		/// @param bv. ByteVector to be expanded.
		static void To(OSVERSIONINFOEXA const& obj, ByteVector& bv)
		{
			bv.Store(obj.dwOSVersionInfoSize, obj.dwMajorVersion, obj.dwMinorVersion, obj.dwBuildNumber, obj.dwPlatformId, obj.wServicePackMajor, obj.wServicePackMinor, obj.wProductType);
		}

		/// Get size required after serialization.
		/// @param obj. Object to be serialized.
		/// @return size_t. Number of bytes used after serialization.
		static size_t Size()
		{
			OSVERSIONINFOEXA* p = nullptr;
			return ByteVector::Size(p->dwOSVersionInfoSize, p->dwMajorVersion, p->dwMinorVersion, p->dwBuildNumber, p->dwPlatformId, p->wServicePackMajor, p->wServicePackMinor, p->wProductType);
		}

		/// Deserialize from ByteView.
		/// @param bv. Buffer with serialized data.
		/// @return OSVERSIONINFOEXA.
		static OSVERSIONINFOEXA From(ByteView& bv)
		{
			OSVERSIONINFOEXA obj = {0,};
			ByteReader{ bv }.Read(obj.dwOSVersionInfoSize, obj.dwMajorVersion, obj.dwMinorVersion, obj.dwBuildNumber, obj.dwPlatformId, obj.wServicePackMajor, obj.wServicePackMinor, obj.wProductType);
			return obj;
		}
	};

	/// overload ByteConverter for HostInfo
	template<>
	struct ByteConverter<HostInfo>
	{
		/// Serialize HostInfo type to ByteVector.
		/// @param obj. Object to be serialized.
		/// @param bv. ByteVector to be expanded.
		static void To(HostInfo const& obj, ByteVector& bv)
		{
			bv.Store(obj.m_ComputerName, obj.m_UserName, obj.m_Domain, obj.m_OsVersionInfo, obj.m_ProcessId, obj.m_IsElevated);
		}

		/// Get size required after serialization.
		/// @param obj. Object to be serialized.
		/// @return size_t. Number of bytes used after serialization.
		static size_t Size(HostInfo const& obj)
		{
			return ByteVector::Size(obj.m_ComputerName, obj.m_UserName, obj.m_Domain, obj.m_OsVersionInfo, obj.m_ProcessId, obj.m_IsElevated);
		}

		/// Deserialize from ByteView.
		/// @param bv. Buffer with serialized data.
		/// @return arithmetic type.
		static HostInfo From(ByteView& bv)
		{
			using T = HostInfo;
			return ByteReader{ bv }.Create(&T::m_ComputerName, &T::m_UserName, &T::m_Domain, &T::m_OsVersionInfo, &T::m_ProcessId, &T::m_IsElevated);
		}
	};
}
