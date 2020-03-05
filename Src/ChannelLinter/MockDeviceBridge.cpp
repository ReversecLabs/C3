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
		std::cout << FSecure::C3::Utils::ConvertLogMessageToConsoleText("", message, nullptr) << std::endl;
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

}
