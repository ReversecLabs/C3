#pragma once

#include "Socket.h"
#include "Common/MWR/CppTools/ByteVector.h"
#include "Common/MWR/CppTools/ByteView.h"

namespace MWR
{
	class DuplexConnection
	{
	public:
		/// Create a duplex connection with address and port
		DuplexConnection(std::string_view addr, uint16_t port);

		/// Create a duplex connection over a socket
		DuplexConnection(ClientSocket sock);

		/// Enable move constructor
		DuplexConnection(DuplexConnection&&) = default;

		/// Enable move assignment
		DuplexConnection& operator =(DuplexConnection&&) = default;

		/// Dtor
		~DuplexConnection();

		/// Start a sending thread
		void StartSending();

		/// Send a message through connection
		void Send(ByteVector message);

		/// Receive data from connection
		ByteVector Receive();

		/// Start processing received data in separate thread
		void StartReceiving(std::function<void(ByteVector)> callback);

		/// Stop sending and receiving
		void Stop();

		/// Check if sending is on
		bool IsSending() const;

	private:
		/// Gets next message queued to send
		ByteVector GetMessage(std::unique_lock<std::mutex>& lock);

		std::atomic_bool m_IsSending;
		std::atomic_bool m_IsReceiving;
		std::thread m_SendingThread;
		std::thread m_ReceivingThread;
		ClientSocket m_ClientSocket;

		std::mutex m_MessagesMutex;
		std::condition_variable m_NewMessage;
		std::queue<ByteVector> m_Messages;
	};
}
