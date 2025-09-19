#pragma once
#include "Common/FSecure/Atlassian/JiraApi.h"

namespace FSecure::C3::Interfaces::Channels
{
	///Implementation of the Jira Issue Channel.
	struct JiraIssue : public Channel<JiraIssue>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		JiraIssue(ByteView arguments);

		/// Destructor
		virtual ~JiraIssue() = default;

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
		/// Set long delay otherwise JiraIssue rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3500ms, s_MaxUpdateDelay = 6500ms;

	protected:
		/// The inbound direction name of data
		std::string m_inboundDirectionName;

		/// The outbound direction name, the opposite of m_inboundDirectionName
		std::string m_outboundDirectionName;

	private:

		enum messageType { COMMENT, ATTACHMENT };


		/// An object encapsulating the Jira API, providing methods allowing the consumer to send and receive messages to JiraIssue, among other things.
		FSecure::Jira m_jiraObj;

		/// Delete the issue we're using for the channel (regardless of whether we created it).
		void DeleteIssue();

		/// Delete all the replies to a message.
		/// @param repliesTs - an array of timestamps of messages to be deleted through DeleteMessage.
		void DeleteObjects(std::vector<std::pair<std::string, int>> const& commentIds);
	};
}
