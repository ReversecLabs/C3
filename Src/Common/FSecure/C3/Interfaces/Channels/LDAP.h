#pragma once

#include <winnt.h>

struct IDirectoryObject;

namespace FSecure::C3::Interfaces::Channels
{
	namespace Detail
	{
		/// @brief RAII wrapper to call CoInitialize / CoUninitialize
		struct ComInitializer
		{
			ComInitializer();

		private:
			static void Deleter(void*);

			std::unique_ptr<void, decltype(&Deleter)> m_Init;
		};

		/// @brief RAII wrapper around ComPtr to call IUnknown::Release
		/// @tparam T
		template<typename T>
		struct ComPtr
		{
			ComPtr(T* ptr) : m_Ptr{ ptr, &Deleter } {}

			T* operator -> () { return m_Ptr.get();  }

		private:
			static void Deleter(T* ptr)
			{
				ptr->Release();
			}

			std::unique_ptr<T, decltype(&Deleter)> m_Ptr;
		};
	}

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

		Detail::ComPtr<IDirectoryObject> CreateDirectoryObject();

		void ClearAttribute(std::wstring const& attribute);

		std::string GetAttributeValue(std::wstring const& attribute);

		void SetAttribute(std::wstring const& attribute, std::wstring const& value);

		size_t CalculateDataSize(ByteView data);

		static std::string EncodeData(ByteView data, size_t dataSize);

		FSecure::ByteVector OnRunCommand(ByteView command) override;

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
		/// The LDAP attribute to save the data too
		std::wstring m_ldapAttribute;
		/// The LDAP attribute to use as the lock
		std::wstring m_ldapLockAttribute;
		/// Maximum packet size
		uint32_t m_maxPacketSize;
		/// Target domain controller to bind to
		std::wstring m_domainController;
		/// An explict LDAP username to bind to
		std::wstring m_username;
		/// The password needed to bind to the target user
		std::wstring m_password;
		/// Distinguished name of the target user
		std::wstring m_userDN;

		/// Initialize COM
		Detail::ComInitializer m_Com;

		/// LDAP directory object used to query AD
		Detail::ComPtr<IDirectoryObject> m_DirObject;
	};
}