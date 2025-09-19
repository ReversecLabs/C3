#pragma once
#include "Common/FSecure/Discord/DiscordApi.h"

namespace FSecure::C3::Interfaces::Channels
{
	///Implementation of the Discord Channel.
	struct Discord : public Channel<Discord>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		Discord(ByteView arguments);

		/// Destructor
		virtual ~Discord() = default;

		/// OnSend callback implementation.
		/// @param packet data to send to Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView packet);

		/// Reads a single C3 packet from Channel.
		/// @return packet retrieved from Channel.
		std::vector<ByteVector> OnReceiveFromChannel();

		/// Get channel capability.
		/// @returns Channel capability in JSON format
		static const char* GetCapability();

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		/// Values used as default for channel jitter. 30 ms if unset. Current jitter value can be changed at runtime.
		/// Set long delay otherwise Discord rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3500ms, s_MaxUpdateDelay = 6500ms;

	protected:
		/// The inbound direction name of data
		std::string m_inboundDirectionName;

		/// The outbound direction name, the opposite of m_inboundDirectionName
		std::string m_outboundDirectionName;

		/// Delete Discord channel.
		void DeleteChannel();

		/// Delete Discord channel messages only.
		void DeleteAllMessages();

	private:
		/// An object encapsulating Discord's API, providing methods allowing the consumer to send and receive messages to Discord, among other things.
		FSecure::Discord m_discordObj;

		/// we're getting the messages we care about from returned messages, saving extra API calls and slowing the channel down
		std::vector<std::string> GetMessagesByDirection(json const& messages, std::string const& direction);

		// get all messages that are a reply to a given message, use existing message json to reduce API calls
		std::vector<std::pair<std::string, std::string>> ReadReplies(json const& messages, std::string const& messageId);
	};
}
