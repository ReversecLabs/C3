#pragma once

#include "Common/FSecure/AsanaApi/AsanaApi.h"

namespace FSecure::C3::Interfaces::Channels
{
	///Implementation of the Asana Channel.
	struct Asana : public Channel<Asana>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		Asana(ByteView arguments);

		/// Destructor
		virtual ~Asana() = default;

		/// OnSend callback implementation.
		/// @param packet data to send to Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView packet);

		/// Reads C3 packets from Channel.
		/// @return packets retrieved from Channel.
		std::vector<ByteVector> OnReceiveFromChannel();

		/// Get channel capability.
		/// @returns Channel capability in JSON format
		static const char* GetCapability();

		/// Values used as default for channel jitter. 30 ms if unset. Current jitter value can be changed at runtime.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3000ms, s_MaxUpdateDelay = 6000ms;
	protected:
		/// The inbound direction name of data
		std::string m_inboundDirectionName;

		/// The outbound direction name, the opposite of m_inboundDirectionName
		std::string m_outboundDirectionName;

	private:
		/// An object encapsulating Asana's API
		FSecure::AsanaApi m_asanaObj;

		// The prefix for all attachments
		FSecure::ByteVector m_attachmentPrefix;
	};
}

