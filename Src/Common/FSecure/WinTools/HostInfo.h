#pragma once

#include "Common/json/json.hpp"


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

		/// Gather host information
		HostInfo();

		/// Deserializing constructor from json
		/// @param json to read from
		HostInfo(const json& json);

		/// Deserializing constructor from ByteView
		/// @param byte view n to read from
		HostInfo(ByteView bv);

		/// Serialize to ByteVector
		/// @returns ByteVector representation of host information
		ByteVector ToByteVector() const;
	};

	/// Overload ostream operator << for HostInfo
	/// @param ostream to write to
	/// @param host info to write
	std::ostream& operator <<(std::ostream& os, HostInfo const& hi);

	/// overload to_json for HostInfo
	/// @param json to write to
	/// @param host info to write
	void to_json(json& j, const HostInfo& hi);
}
