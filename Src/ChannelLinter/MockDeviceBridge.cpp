#include "stdafx.h"
#include "MockDeviceBridge.h"

namespace FSecure::C3::Linter
{
	MockDeviceBridge::MockDeviceBridge(std::shared_ptr<Device> device ) :
		m_Device(move(device))
	{
	}

	void MockDeviceBridge::OnAttach()
	{
		GetDevice()->OnAttach(shared_from_this());
	}

	void MockDeviceBridge::Detach()
	{
		m_Device.reset();
	}

	void MockDeviceBridge::Close()
	{
		Detach();
	}

	void MockDeviceBridge::OnReceive()
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::PassNetworkPacket(ByteView packet)
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::OnPassNetworkPacket(ByteView packet)
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::PostCommandToConnector(ByteView command)
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::OnCommandFromConnector(ByteView command)
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	FSecure::ByteVector MockDeviceBridge::RunCommand(ByteView command)
	{
		return GetDevice()->OnRunCommand(command);
	}

	FSecure::ByteVector MockDeviceBridge::WhoAreYou()
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::Log(LogMessage const& message)
	{
		static std::mutex mutex;
		std::lock_guard lock(mutex);
		std::cout << FSecure::C3::Utils::ConvertLogMessageToConsoleText("", message, "") << std::endl;
	}

	void MockDeviceBridge::SetUpdateDelay(std::chrono::milliseconds minUpdateDelay, std::chrono::milliseconds maxUpdateDelay)
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::SetUpdateDelay(std::chrono::milliseconds updateDelay)
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::SetErrorStatus(std::string_view errorMessage)
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	std::string MockDeviceBridge::GetErrorStatus()
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	std::shared_ptr<FSecure::C3::Device> MockDeviceBridge::GetDevice() const
	{
		return m_Device;
	}

	void MockDeviceBridge::Send(ByteView blob)
	{
		auto sender = GetChunkSender(blob);
		for (auto noProgressCounter = 0; noProgressCounter < 10; ++noProgressCounter)
		{
			if (sender.Send())
				noProgressCounter = 0;

			if (sender.IsDone())
				return;
		}

		throw std::runtime_error("Cannot send data");
	}

	std::vector<FSecure::ByteVector> MockDeviceBridge::Receive(size_t minExpectedSize)
	{
		auto receiver = GetChunkReceiver();
		for (auto noProgressCounter = 0; noProgressCounter < 10; ++noProgressCounter)
		{
			if (receiver.Receive())
				noProgressCounter = 0;

			if (receiver.Size() >= minExpectedSize)
				return receiver.GetPackets();
		}

		throw std::runtime_error("Cannot receive data");
	}

	FSecure::C3::Linter::MockDeviceBridge::ChunkSender MockDeviceBridge::GetChunkSender(ByteView blob)
	{
		return { *m_Device.get(), m_QoS, blob };
	}

	FSecure::C3::Linter::MockDeviceBridge::ChunkReceiver MockDeviceBridge::GetChunkReceiver()
	{
		return { *m_Device.get(), m_QoS };
	}

	MockDeviceBridge::ChunkSender::ChunkSender(Device& device, QualityOfService& qos, ByteView blob)
		: m_Device{ device }, m_Splitter{ qos.GetPacketSplitter(blob) }
	{

	}

	bool MockDeviceBridge::ChunkSender::Send()
	{
		auto sent = m_Device.OnSendToChannelInternal(m_Splitter.NextChunk());
		return m_Splitter.Update(sent);
	}

	bool MockDeviceBridge::ChunkSender::IsDone()
	{
		return !m_Splitter.HasMore();
	}


	MockDeviceBridge::ChunkReceiver::ChunkReceiver(Device& device, QualityOfService& qos)
		: m_Device{ device }, m_QoS{ qos }
	{

	}

	bool MockDeviceBridge::ChunkReceiver::Receive()
	{
		auto ret = false;
		std::this_thread::sleep_for(m_Device.GetUpdateDelay());
		for (auto&& chunk : static_cast<C3::AbstractChannel&>(m_Device).OnReceiveFromChannelInternal())
		{
			if (m_QoS.PushReceivedChunk(chunk))
				ret = true;

			if (auto packet = m_QoS.GetNextPacket(); !packet.empty()) // this form will ensure that packets are returned in same order they are available.
				m_Packets.emplace_back(std::move(packet));
		}

		return ret;
	}

	size_t MockDeviceBridge::ChunkReceiver::Size()
	{
		return m_Packets.size();
	}

	std::vector<FSecure::ByteVector> const& MockDeviceBridge::ChunkReceiver::GetPackets()
	{
		return m_Packets;
	}
}
