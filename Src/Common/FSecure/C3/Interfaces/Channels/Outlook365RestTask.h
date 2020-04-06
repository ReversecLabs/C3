#pragma once

#include "Common/CppRestSdk/include/cpprest/http_client.h"																//< For CppRestSdk.

namespace FSecure::C3::Interfaces::Channels
{
	/// Implementation of the Outlook365 REST tasks Device.
	class Outlook365RestTask : public Channel<Outlook365RestTask>
	{
	public:
		/// Public constructor.
		/// @param arguments factory arguments.
		Outlook365RestTask(ByteView arguments);

		/// OnSend callback implementation.
		/// @param blob data to send to Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView blob);

		/// Reads a single C3 packet from Channel.
		/// @return packet retrieved from Channel.
		ByteVector OnReceiveFromChannel();

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		/// Get channel capability.
		/// @returns ByteView view of channel capability.
		static ByteView GetCapability();

		/// Values used as default for channel jitter. 30 ms if unset. Current jitter value can be changed at runtime.
		/// Set long delay otherwise O365 rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3500ms, s_MaxUpdateDelay = 6500ms;

	protected:

		/// Removes all tasks from server.
		/// @param ByteView unused.
		/// @returns ByteVector empty vector.
		ByteVector RemoveAllTasks(ByteView);

		/// Remove one task from server.
		/// @param id of task.
		void RemoveTask(std::string const& id);

		/// Requests a new access token using the refresh token
		/// @throws std::exception if token cannot be refreshed.
		void RefreshAccessToken();

		/// In/Out names on the server.
		std::string m_InboundDirectionName, m_OutboundDirectionName;

		/// Stores HTTP configuration (proxy, OAuth, etc).
		web::http::client::http_client_config m_HttpConfig;

		/// Password for user with o365 subscription.
		std::string m_Password;

		/// Used to delay every channel instance in case of server rate limit.
		/// Set using information from 429 Too Many Requests header.
		static std::atomic<std::chrono::steady_clock::time_point> s_TimePoint;
	};
}
