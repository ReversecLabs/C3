#pragma once
#include "Common/MWR/Slack/SlackApi.h"

namespace MWR::C3::Interfaces::Channels
{
	///Implementation of the Slack Channel.
	struct Slack : public Channel<Slack>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		Slack(ByteView arguments);

		/// OnSend callback implementation.
		/// @param packet data to send to Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView packet);

		/// Reads a single C3 packet from Channel.
		/// @return packet retrieved from Channel.
		ByteVector OnReceiveFromChannel();

		/// Get channel capability.
		/// @returns ByteView view of channel capability.
		static ByteView GetCapability();

		/// Values used as default for channel jitter. 30 ms if unset. Current jitter value can be changed at runtime.
		/// Set long delay otherwise slack rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateFrequency = 3500ms, s_MaxUpdateFrequency = 6500ms;

	protected:
		/// The inbound direction name of data
		std::string m_inboundDirectionName;

		/// The outbound direction name, the opposite of m_inboundDirectionName
		std::string m_outboundDirectionName;

	private:
		/// An object encapsulating Slack's API, providing methods allowing the consumer to send and receive messages to slack, among other things.
		MWR::Slack m_slackObj;

		/// Delete all the replies to a message.
		/// @param repliesTs - an array of timestamps of messages to be deleted through DeleteMessage.
		void DeleteReplies(std::vector<std::string> const& repliesTs);
	};
}
