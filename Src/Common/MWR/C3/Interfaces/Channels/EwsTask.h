#pragma once

namespace MWR::C3::Interfaces::Channels
{
	/// Implementation of the EWS Tasks Channel.
	class EwsTask : public Channel<EwsTask>
	{
	public:
		/// Constructor.
		/// @param arguments factory arguments.
		EwsTask(ByteView arguments);

		/// A public destructor.
		~EwsTask();

		/// Sending callback implementation.
		/// @param blob packet to send to the Channel.
		/// @returns size_t number of bytes successfully written.
		size_t OnSendToChannel(ByteView blob) noexcept(false) override;

		/// Receiving callback implementation.
		/// @returns ByteVector received blob of data.
		ByteVector OnReceiveFromChannel() override;

		/// Get channel capability.
		/// @returns ByteView view of channel capability.
		static ByteView GetCapability();

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

	protected:
		/// Removes all tasks from server.
		/// @param ByteView unused.
		/// @return command result, empty vector.
		ByteVector RemoveAllTasks(ByteView);

		/// Flow direction names.
		std::string m_InboundDirectionName, m_OutboundDirectionName;

		/// Office 365 credentials
		std::string m_EwsServerUri, m_EwsUserName, m_EwsPassword;
	};
}
