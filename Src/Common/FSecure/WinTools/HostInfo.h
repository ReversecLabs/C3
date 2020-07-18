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
		RTL_OSVERSIONINFOEXW m_OsVersionInfo;									///< MS windows version info
		DWORD m_ProcessId;														///< Process Id
		bool m_IsElevated;														///< Is process run with elevated rights

		/// Gather info about host.
		static HostInfo Gather();

		/// Aggregate constructor.
		HostInfo(std::string computerName, std::string userName, std::string domain, RTL_OSVERSIONINFOEXW osVersionInfo, DWORD processId, bool isElevated);

		/// Constructor from json
		/// @param json to read from
		HostInfo(const json& json);
	};

	/// overload to_json for HostInfo
	/// @param json to write to
	/// @param host info to write
	void to_json(json& j, const HostInfo& hi);

	/// overload ByteConverter for RTL_OSVERSIONINFOEXW. szCSDVersion and wSuiteMask are omitted.
	template<>
	struct ByteConverter<RTL_OSVERSIONINFOEXW> : TupleConverter<RTL_OSVERSIONINFOEXW>
	{
		/// Serialization of RTL_OSVERSIONINFOEXW type to/from ByteVector.
		/// @param obj. Object to be serialized.
		static auto Convert(RTL_OSVERSIONINFOEXW const& obj)
		{
			return Utils::MakeConversionTuple(
				obj.dwOSVersionInfoSize,
				obj.dwMajorVersion,
				obj.dwMinorVersion,
				obj.dwBuildNumber,
				obj.dwPlatformId,
				obj.wServicePackMajor,
				obj.wServicePackMinor,
				obj.wProductType
			);
		}

		/// Deserialize from ByteView.
		/// Special version of From must be provided, because some of not important members are omitted at serialization.
		/// @param bv. Buffer with serialized data.
		/// @return RTL_OSVERSIONINFOEXW.
		static RTL_OSVERSIONINFOEXW From(ByteView& bv)
		{
			RTL_OSVERSIONINFOEXW obj = {0,};
			ByteReader{ bv }.Read(
				obj.dwOSVersionInfoSize,
				obj.dwMajorVersion,
				obj.dwMinorVersion,
				obj.dwBuildNumber,
				obj.dwPlatformId,
				obj.wServicePackMajor,
				obj.wServicePackMinor,
				obj.wProductType
			);
			return obj;
		}
	};

	/// overload ByteConverter for HostInfo
	template<>
	struct ByteConverter<HostInfo> : TupleConverter<HostInfo>
	{
		/// Serialization of HostInfo type to/from ByteVector.
		/// @param obj. Object to be serialized.
		static auto Convert(HostInfo const& obj)
		{
			return Utils::MakeConversionTuple(obj.m_ComputerName, obj.m_UserName, obj.m_Domain, obj.m_OsVersionInfo, obj.m_ProcessId, obj.m_IsElevated);
		}
	};
}
