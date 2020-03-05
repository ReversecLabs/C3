#pragma once

namespace FSecure::C3::Interfaces::Channels
{
	/// Implementation of the FileSharing via UNC paths Channel.
	class UncShareFile : public Channel<UncShareFile>
	{
	public:
		/// Public constructor.
		/// @param arguments factory arguments.
		UncShareFile(ByteView arguments);

		/// OnSend callback implementation.
		/// @param blob data to send to Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView blob);

		/// Reads a single C3 packet from Channel.
		/// @return packet retrieved from Channel.
		std::vector<ByteVector> OnReceiveFromChannel();

		/// Get channel capability.
		/// @returns ByteView view of channel capability.
		static ByteView GetCapability();

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

	protected:
		/// Removes all tasks from server.
		void RemoveAllPackets();

		/// Check if file should processed.
		/// @param path to file to be checked.
		/// @returns true if channel instance should handle file, false otherwise.
		bool BelongToChannel(std::filesystem::path const& path) const;

		/// Removes file.
		/// @param path to file to be removed.
		void RemoveFile(std::filesystem::path const& path);

		/// Flow direction names.
		std::string m_InboundDirectionName, m_OutboundDirectionName;

		/// Path of the directory to store the C2 messages.
		std::filesystem::path m_FilesystemPath;
	};
}
