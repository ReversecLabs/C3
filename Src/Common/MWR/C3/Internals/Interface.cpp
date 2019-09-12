#include "StdAfx.h"
#include "Interface.h"
#include "Core/DeviceBridge.h" // TODO it would be great to remove core dependency. PTAL Close method
#include "Core/ConnectorBridge.h"
#include "Core/Relay.h"
#include "Core/GateRelay.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::AbstractPeripheral::OnReceive()
{
	if (auto bridge = GetBridge(); bridge)
		if (auto command = OnReceiveFromPeripheral(); !command.empty())
			bridge->PostCommandToConnector(command);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::AbstractChannel::OnReceive()
{
	if (auto bridge = GetBridge(); bridge)
		if (auto packet = OnReceiveFromChannel(); !packet.empty())
			bridge->PassNetworkPacket(packet);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Device::SetUpdateDelay(std::chrono::milliseconds minUpdateDelayInMs, std::chrono::milliseconds maxUpdateDelayInMs)
{
	// Sanity checks.
	if (minUpdateDelayInMs > maxUpdateDelayInMs)
		throw std::invalid_argument{ OBF("maxUpdateDelay must be greater or equal to minUpdateDelay.") };
	if (minUpdateDelayInMs < 30ms)
		throw std::invalid_argument{ OBF("minUpdateDelay must be greater or equal to 30ms.") };

	std::lock_guard<std::mutex> guard(m_UpdateDelayMutex);
	m_MinUpdateDelay = minUpdateDelayInMs;
	m_MaxUpdateDelay = maxUpdateDelayInMs;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Device::SetUpdateDelay(std::chrono::milliseconds frequencyInMs)
{
	std::lock_guard<std::mutex> guard(m_UpdateDelayMutex);
	m_MinUpdateDelay = frequencyInMs;
	m_MaxUpdateDelay = m_MinUpdateDelay;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::chrono::milliseconds MWR::C3::Device::GetUpdateDelay() const
{
	std::lock_guard<std::mutex> guard(m_UpdateDelayMutex);
	return m_MinUpdateDelay != m_MaxUpdateDelay ? MWR::Utils::GenerateRandomValue(m_MinUpdateDelay, m_MaxUpdateDelay) : m_MinUpdateDelay;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Device::OnRunCommand(ByteView command)
{
	switch (command.Read<uint16_t>())
	{
		case static_cast<uint16_t>(MWR::C3::Core::Relay::Command::Close):
		return Close(), ByteVector{};
	case static_cast<uint16_t>(MWR::C3::Core::Relay::Command::UpdateJitter) :
	{
		auto [minVal, maxVal] = command.Read<float, float>();
		return SetUpdateDelay(MWR::Utils::ToMilliseconds(minVal), MWR::Utils::ToMilliseconds(maxVal)), ByteVector{};
	}
	default:
		throw std::runtime_error(OBF("Device received an unknown command"));
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::AbstractConnector::OnRunCommand(ByteView command)
{
	switch (command.Read<uint16_t>())
	{
		case static_cast<uint16_t>(-1) :
			return TurnOff(), ByteVector{};
		default:
			throw std::runtime_error(OBF("AbstractConnector received an unknown command"));
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Device::Close() // Closing mechanism was not originaly ment for device itself. It must call relay methods to remove itself. New mechanism that does not need to know relay must be introduced.
{
	auto bridge = std::static_pointer_cast<Core::DeviceBridge>(GetBridge());
	auto relay = std::static_pointer_cast<Core::Relay>(bridge->GetRelay());
	relay->DetachDevice(bridge->GetDid());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::AbstractConnector::TurnOff()
{
	auto bridge = std::static_pointer_cast<Core::ConnectorBridge>(GetBridge());
	auto gateway = std::static_pointer_cast<Core::GateRelay>(bridge->GetGateRelay());
	gateway->TurnOffConnector(bridge->GetNameHash());
}
