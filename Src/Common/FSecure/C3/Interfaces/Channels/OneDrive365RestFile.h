#pragma once

#include "Office365.h"

namespace FSecure::C3::Interfaces::Channels
{
	class OneDrive365RestFile : public Channel<OneDrive365RestFile>, public Office365<OneDrive365RestFile>
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

		/// Values used as default for channel jitter. 30 ms if unset. Current jitter value can be changed at runtime.
		/// Set long delay otherwise O365 rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3500ms, s_MaxUpdateDelay = 6500ms;

		/// Endpoint used to add file to OneDrive
		static Crypto::String RootEndpoint;

		/// Endpoints used by Office365 methods.
		static Crypto::String ItemEndpoint;
		static Crypto::String ListEndpoint;
		static Crypto::String TokenEndpoint;
		static Crypto::String Scope;
	};
}
