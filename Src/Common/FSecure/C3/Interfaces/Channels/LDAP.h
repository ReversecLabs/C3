#pragma once

#include <winnt.h>

struct IDirectoryObject;

namespace FSecure::C3::Interfaces::Channels
{
	///Implementation of the LDAP Channel.
	struct LDAP : public Channel<LDAP>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		LDAP(ByteView arguments);
		/// Destructor
		virtual ~LDAP() = default;
		/// OnSend callback implementation.
		/// @param packet data to send to Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView packet);
		/// Reads a single C3 packet from Channel.
		/// @return packet retrieved from Channel.
		ByteVector OnReceiveFromChannel();

		void CreateDirectoryObject();

		void ClearAttribute(std::wstring const& attribute);
		std::string GetAttributeValue(std::wstring const& attribute);

		void SetAttribute(std::wstring const& attribute, std::wstring const& value);

		size_t CalculateDataSize(ByteView data);
		std::string EncodeData(ByteView data, size_t dataSize);
		/// Get channel capability.
		/// @returns Channel capability in JSON format
		static const char* GetCapability();
		/// Values used as default for channel jitter. 30 ms if unset. Current jitter value can be changed at runtime.
		/// Set long delay otherwise LDAP rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3500ms, s_MaxUpdateDelay = 6500ms;


	protected:
		/// The inbound direction name of data
		std::string m_inboundDirectionName;
		/// The outbound direction name, the opposite of m_inboundDirectionName
		std::string m_outboundDirectionName;
		/// The LDAP atttribute to save the data too
		std::wstring m_ldapAttribute;
		/// The LDAP atttribute to use as the lock
		std::wstring m_ldapLockAttribute;
		/// Maximum packet size
		uint32_t m_maxPacketSize;
		/// Maximum packet size
		std::wstring m_domainController;
		/// The LDAP atttribute to use as the lock
		std::string m_username;
		/// The LDAP atttribute to use as the lock
		std::string m_password;
		
		
		/// LDAP dircetory object used to query AD
		IDirectoryObject* pDirObject;
	};

	//private:
	//	///The directory object
	//	//IDirectoryObject *pDirObject;
	//	///result
	//	HRESULT hr;
	//};


}