#include "StdAfx.h"
#include "Relay.h"
#include "DeviceBridge.h"
#include "Common/MWR/CppTools/ByteView.h"
#include "Common/MWR/C3/Internals/InterfaceFactory.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Core::Relay::Relay(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory, Crypto::PrivateKey const& decryptionKey, Crypto::SymmetricKey const& broadcastKey,
	BuildId buildId, AgentId agentId)
	: Distributor{ callbackOnLog, decryptionKey, broadcastKey }
	, m_BuildId{ buildId }
	, m_AgentId{ agentId }
	, m_InterfaceFactory{ interfaceFactory }
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<MWR::C3::Core::DeviceBridge> MWR::C3::Core::Relay::AttachDevice(std::shared_ptr<MWR::C3::Core::DeviceBridge> device)
{
	m_Devices.TryAdd(
		[did = device->GetDid()](std::weak_ptr<DeviceBridge> const& c)
		{
			auto sp = c.lock();
			return sp ? sp->GetDid() == did : false;
		}, device);

	device->OnAttach();

	// Current implementation just runs OnReceive in a separate thread. In the future we might implement some single threaded solutions (i.e. schedulers).
	device->StartUpdatingInSeparateThread();
	return device;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<MWR::C3::Core::DeviceBridge> MWR::C3::Core::Relay::CreateAndAttachDevice(DeviceId iid, HashT deviceNameHash, bool isNegotiationChannel, ByteView commandLine, bool negotiationClient /*= false*/)
{
	// Find the right factory, call it and attach returned Device.
	if (auto deviceData = InterfaceFactory::Instance().GetInterfaceData<AbstractChannel>(deviceNameHash); deviceData)
	{
		ByteVector helper;
		if (isNegotiationChannel)
		{
			auto readView = commandLine;
			auto negotiationId = readView.Read<ByteView>();
			helper.reserve(commandLine.size() + negotiationId.size() + sizeof(std::uint32_t));
			auto generatedId = MWR::Utils::GenerateRandomString(negotiationId.size());
			if (negotiationClient)
				helper.Write(generatedId, negotiationId);
			else
				helper.Write(negotiationId, generatedId);

			helper.Concat(readView);
			commandLine = helper;
		}
		return AttachDevice(std::make_shared<DeviceBridge>(std::static_pointer_cast<Relay>(shared_from_this()), iid, deviceNameHash, deviceData->m_Builder(commandLine), isNegotiationChannel, negotiationClient, commandLine));
	}
	else if (auto deviceData = InterfaceFactory::Instance().GetInterfaceData<AbstractPeripheral>(deviceNameHash); deviceData)
		return AttachDevice(std::make_shared<DeviceBridge>(std::static_pointer_cast<Relay>(shared_from_this()), iid, deviceNameHash, deviceData->m_Builder(commandLine)));

	// Couldn't find it.
	throw std::runtime_error{ OBF("Couldn't find factory for Device of hash '") + std::to_string(deviceNameHash) + OBF("'.") };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Core::Relay::DetachDevice(DeviceId const& iidOfDeviceToDetach)
{
	// Find specified Device.
	m_Devices.Remove([&iidOfDeviceToDetach](std::weak_ptr<DeviceBridge> const& c)
		{
			if (auto ri = c.lock(); ri && ri->GetDid() == iidOfDeviceToDetach)
			{
				ri->Detach();
				return true;
			}

			return false;
		});
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<MWR::C3::Core::DeviceBridge> MWR::C3::Core::Relay::FindDevice(DeviceId did)
{
	std::shared_ptr<MWR::C3::Core::DeviceBridge> retVal;
	m_Devices.Find([&did, &retVal](std::weak_ptr<DeviceBridge> const& c)
		{
			if (auto ri = c.lock(); ri && ri->GetDid() == did)
			{
				retVal = std::move(ri);
				return true;
			}

			return false;
		});

	return retVal;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Core::Relay::Close()
{
	m_Devices.For([](auto c)
		{
			if (auto ri = c.lock(); ri)
				ri->Detach();

			return true;
		});

	m_Devices.Clear();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Core::Relay::Join()
{
	auto self = shared_from_this();
	// The main thread has a shared_ptr on which that Join method is called ->
	while (self.use_count() > 2)
		std::this_thread::sleep_for(1s);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Core::Relay::CreateRoute(ByteView args)
{
	auto [ridStr, didStr] = args.Read<std::string, std::string>();
	auto channel = m_Devices.Find([did = DeviceId{ didStr }](auto const& e) { auto l = e.lock(); return l ? l->GetDid() == did : false; }).lock();
	if (!channel)
		throw std::runtime_error{ OBF("Device not found") };

	AddRoute(RouteId::FromString(ridStr), channel);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void MWR::C3::Core::Relay::RemoveRoute(ByteView args)
{
	auto rid = RouteId::FromString(args.Read<std::string>());
	RouteManager::RemoveRoute(rid);
}
