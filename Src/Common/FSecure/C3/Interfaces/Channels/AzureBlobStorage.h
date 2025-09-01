#pragma once
#include "Common/FSecure/AzureBlobStorage/AzureBlobStorageApi.h"

namespace FSecure::C3::Interfaces::Channels
{
	///Implementation of the AzureBlobStorage Channel.
	struct AzureBlobStorage : public Channel<AzureBlobStorage>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		AzureBlobStorage(ByteView arguments);

		/// Destructor
		virtual ~AzureBlobStorage() = default;

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

		/// Values used as default for channel jitter. 30 ms if unset. Current jitter value can be changed at runtime.
		/// Set long delay otherwise AzureBlobStorage rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3500ms, s_MaxUpdateDelay = 6500ms;

	protected:
		/// The inbound direction name of data
		std::string m_inboundDirectionName;

		/// The outbound direction name, the opposite of m_inboundDirectionName
		std::string m_outboundDirectionName;

	private:
		/// An object encapsulating AzureBlobStorage's API, providing methods allowing the consumer to send and receive messages to AzureBlobStorage, among other things.
		FSecure::AzureBlobStorage m_AzureBlobStorageObj;
	};
}
#pragma once
