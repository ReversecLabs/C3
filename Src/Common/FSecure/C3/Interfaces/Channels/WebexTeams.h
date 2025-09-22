#pragma once

#include "Common/FSecure/WebexTeams/WebexTeamsApi.h"

namespace FSecure::C3::Interfaces::Channels
{
	struct WebexTeams : public Channel<WebexTeams>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		WebexTeams(ByteView arguments);

		/// Destructor
		virtual ~WebexTeams() = default;

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

		/// Values used as default for channel jitter. 
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3500ms, s_MaxUpdateDelay = 6500ms;

	protected:
		/// The Webex roomId's of the inbound and outbound channels
		std::string m_inboundDirectionRoomId, m_outboundDirectionRoomId;

		/// Filename of the attachments we send
		std::string m_attachmentFileName;

		/// MIME type of the attachments we send
		std::string m_attachmentMimeType;

		/// Boolean controlling whether we use attachments for faster communication
		boolean m_useAttachments;

		/// Prefix to all attachments
		ByteVector m_attachmentPrefix;

	private:
		/// An object encapsulating Webex's API, providing methods allowing the consumer to send and receive messages to Webex, among other things.
		FSecure::WebexTeamsApi m_webexApi;
	};
}
