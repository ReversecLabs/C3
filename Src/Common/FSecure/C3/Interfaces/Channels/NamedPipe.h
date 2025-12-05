#pragma once
namespace FSecure::C3::Interfaces::Channels
{
	/// Implementation of a File Channel.
	struct NamedPipe : public Channel<NamedPipe>
	{

		/// Public constructor.
		/// @param arguments factory arguments.

		NamedPipe(ByteView arguments);
		/// OnSend callback implementation. Called every time attached Relay wants to send a packet through this Channel Device. @see Device::OnSendToChannelInternal.
		/// @param packet data to send through the Channel.
		/// @return number of bytes successfully sent through the Channel. In this channel this call Must send all of the bytes as you cannot reconnect to the same named pipe.
		size_t OnSendToChannel(FSecure::ByteView packet);

		/// Reads a single C3 packet from Channel. Periodically called by attached Relay. Implementation should read the data (or return an empty buffer if there's nothing in the Channel waiting to read) and leave as soon as possible.
		/// @return ByteVector that contains a single packet retrieved from Channel.
		ByteVector OnReceiveFromChannel();

		/// Describes Channels creation parameters and custom Commands.
		/// @return Channel's capability description in JSON format.
		static const char* GetCapability();

		/// Explicit values used as the defaults for Channel's UpdateDelayJitter. Values can be changed later, at runtime.
		constexpr static std::chrono::milliseconds s_MinUpdateDelay = 30ms, s_MaxUpdateDelay = 30ms;
	protected:
		/// The inbound direction name of data
		std::string m_inboundDirectionName;

		/// The outbound direction name, the opposite of m_inboundDirectionName
		std::string m_outboundDirectionName;
	private:
		/// a string indicating the address and prefix used for the pipename
		std::string m_pipeNamePrefix;

		/// The inbound pipe name
		std::string m_readPipeName;

		/// The outbound pipe name
		std::string m_writePipeName;

		// marked as true when client disconnects to restarted the named pipe.
		bool m_isDisconnected;

		/// handles to created pipes
		HANDLE m_hReadPipe;
		HANDLE m_hWritePipe;

		/// allow the relay to determine whether it is a client or server.
		BOOL m_isServer = false;
		
		/// contains logic for a client or server relay to either wait for a connection to the named pipe or open the pipe with CreateFile.
		HANDLE ConnectOrOpen(BOOL read);

		/// calls DisconnectNamedPipe if this is a server, or closeHandle if it is a client.
		void DisconnectOrClose();

		/// Creates the server side pipes
		void CreateServerPipes();

		/// Creates the client side pipes
		BOOL CreateClientPipes();
	};
}
