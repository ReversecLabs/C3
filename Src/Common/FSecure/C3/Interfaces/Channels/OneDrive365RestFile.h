#pragma once

#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/Constants.h"				//< For CppRestSdk.
namespace FSecure::C3::Interfaces::Channels
{
	/// Implementation of the OneDrive 365 REST file Channel.
	class OneDrive365RestFile : public Channel<OneDrive365RestFile>
	{
	public:
		/// Public constructor.
		/// @param arguments factory arguments.
		OneDrive365RestFile(ByteView arguments);

		/// OnSend callback implementation.
		/// @param blob data to send to Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView blob);

		/// Reads a single C3 packet from Channel.
		/// @return packet retrieved from Channel.
		std::vector<ByteVector> OnReceiveFromChannel();

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		/// Get channel capability.
		/// @returns ByteView view of channel capability.
		static ByteView GetCapability();

		/// Values used as default for channel jitter. 30 ms if unset. Current jitter value can be changed at runtime.
		/// Set long delay otherwise O365 rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 1000ms, s_MaxUpdateDelay = 1000ms;

	protected:
		/// Removes all file from server.
		/// @param ByteView unused.
		/// @returns ByteVector empty vector.
		ByteVector RemoveAllFiles(ByteView);

		/// Remove one file from server.
		/// @param id of task.
		void RemoveFile(std::string const& id);

		/// Requests a new access token using the refresh token
		/// @throws std::exception if token cannot be refreshed.
		void RefreshAccessToken();

		/// In/Out names on the server.
		std::string m_InboundDirectionName, m_OutboundDirectionName;

		/// Username, password, client key and token for authentication.
		std::string m_username, m_password, m_clientKey, m_token;

		/// Store any relevant proxy info
		WinHttp::WebProxy m_ProxyConfig;


		/// Used to delay every channel instance in case of server rate limit.
		/// Set using information from 429 Too Many Requests header.
		static std::atomic<std::chrono::steady_clock::time_point> s_TimePoint;
	};
}
