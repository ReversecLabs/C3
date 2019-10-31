#include "stdafx.h"
#include "MockDeviceBridge.h"

namespace MWR::C3::Linter
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
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::Close()
	{
		throw std::logic_error("The method or operation is not implemented.");
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

	MWR::ByteVector MockDeviceBridge::RunCommand(ByteView command)
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	MWR::ByteVector MockDeviceBridge::WhoAreYou()
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::Log(LogMessage const& message)
	{
		static std::mutex mutex;
		std::lock_guard lock(mutex);
		std::cout << MWR::C3::Utils::ConvertLogMessageToConsoleText("", message, nullptr) << std::endl;
	}

	void MockDeviceBridge::SetUpdateFrequency(std::chrono::milliseconds minUpdateFrequencyInMs, std::chrono::milliseconds maxUpdateFrequencyInMs)
	{
		throw std::logic_error("The method or operation is not implemented.");
	}

	void MockDeviceBridge::SetUpdateFrequency(std::chrono::milliseconds frequencyInMs)
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

	std::shared_ptr<MWR::C3::Device> MockDeviceBridge::GetDevice() const
	{
		return m_Device;
	}

}
