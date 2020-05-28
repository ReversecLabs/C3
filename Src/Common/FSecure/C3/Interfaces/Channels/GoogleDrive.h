#pragma once
#include "Common/FSecure/GoogleDrive/GoogleDriveApi.h"

namespace FSecure::C3::Interfaces::Channels
{
	///Implementation of the Google Drive Channel.
	struct GoogleDrive : public Channel<GoogleDrive>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		GoogleDrive(ByteView arguments);

		/// Destructor
		virtual ~GoogleDrive() = default;

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
		/// Set long delay otherwise Google Drive rate limit will heavily impact channel.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 3500ms, s_MaxUpdateDelay = 6500ms;

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

	protected:
		/// The inbound direction name of data
		std::string m_inboundDirectionName;

		/// The outbound direction name, the opposite of m_inboundDirectionName
		std::string m_outboundDirectionName;

		/// Uploads file.
		/// @param path to file to be uploaded.
		void UploadFile(ByteView args);

		/// Delete all files relating to the channel.
		void DeleteAllFiles();

	private:
		/// An object encapsulating Google Drive's API, providing methods allowing the consumer to upload and download files from GoogleDrive, among other things.
		FSecure::GoogleDrive m_googledriveObj;
	};
}
