#include "StdAfx.h"
#include "NodeRelay.h"
#include "DeviceBridge.h"
#include "Common/FSecure/CppTools/ByteView.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<FSecure::C3::Core::NodeRelay> FSecure::C3::Core::NodeRelay::CreateAndRun(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory,
	Crypto::PublicSignature const& gatewaySignature, Crypto::SymmetricKey const& broadcastKey, std::vector<ByteVector> const& gatewayInitialPackets, BuildId buildId, AgentId agentId,
	Crypto::AsymmetricKeys const& asymmetricKeys)
{
	// Make one.
	auto relay = std::shared_ptr<NodeRelay>{ new NodeRelay{ callbackOnLog, interfaceFactory, gatewaySignature, broadcastKey, buildId, agentId, asymmetricKeys} };

	// Perform all initial Commands.
	if (gatewayInitialPackets.empty())
		throw std::invalid_argument{ OBF("No initial Command") };

	auto args = ByteView{ gatewayInitialPackets[0] };
	auto isNegChannel = args.Read<bool>();
	auto deviceHash = args.Read<HashT>();
	auto dev = relay->CreateAndAttachDevice(DeviceId{ 0 }, deviceHash, isNegChannel, args, true);


	// Send IC packet.
	if (isNegChannel)
		relay->NegotiateChannel(dev);
	else
		relay->InitializeRoute();

	// All fine and dandy.
	return relay;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::NodeRelay::NodeRelay(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory,
	Crypto::PublicSignature const& gatewaySignature, Crypto::SymmetricKey const& broadcastKey, BuildId buildId, AgentId agentId, Crypto::AsymmetricKeys const& asymmetricKeys)
	: Relay{ callbackOnLog, interfaceFactory, asymmetricKeys.first, broadcastKey, buildId, agentId }
	, m_GatewaySignature{ gatewaySignature }
	, m_GatewayEncryptionKey{ Crypto::ConvertToKey(gatewaySignature) }
	, m_MyEncryptionKey{ asymmetricKeys.second }
{
	Log({ OBF("Agent Id: ") + m_AgentId.ToString(), LogMessage::Severity::Information });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::OnProtocolS2G(ByteView packet0, std::shared_ptr<DeviceBridge> sender)
{
	auto grc = GetGatewayReturnChannel();
	if (!grc)
		std::runtime_error{ OBF("No GRC.") };

	if (grc == sender)
		throw std::runtime_error{ OBF("S2G packet received from GRC.") };

	// Expensive search on NodeRelay.
	if (sender->IsChannel() && !FindRouteByOutgoingChannel(sender->GetDid()))
		throw std::runtime_error{ OBF("S2G packet received from device that has no route attached.") };

	LockAndSendPacket(packet0, grc);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::OnProtocolG2A(ByteView packet0, std::shared_ptr<DeviceBridge> sender)
{
	try
	{
		// Verify message.
		auto veryfiedMessage = Crypto::VerifyMessage(packet0.SubString(1), m_GatewaySignature);
		auto msgView = ByteView{ veryfiedMessage };

		// Parse recipient identifier.
		if (auto routeId = msgView.Read<RouteId>(); routeId.GetAgentId() == m_AgentId)
		{
			// addressed to me
			auto decryptedMessage = Crypto::DecryptAndAuthenticate(msgView, m_GatewayEncryptionKey, m_DecryptionKey);
			ProceduresG2X::RequestHandler::ParseRequestAndHandleIt(sender, routeId, decryptedMessage);
		}
		else
			// Not addressed to me -> packet needs to be passed further.
			MultiSendPacketFurtherThroughRouteId(packet0, routeId);

	}
	catch (std::exception& exception)
	{
		throw std::runtime_error{ OBF_STR("Failed to parse G2A packet. ") + exception.what() };
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::OnProtocolG2R(ByteView packet0, std::shared_ptr<DeviceBridge> sender)
{
	try
	{
		// Verify message.
		auto veryfiedMessage = Crypto::VerifyMessage(packet0.SubString(1), m_GatewaySignature);
		auto msgView = ByteView{ veryfiedMessage };

		// Parse recipient identifier.
		auto routeId = msgView.Read<RouteId>();
		ProceduresG2X::RequestHandler::ParseRequestAndHandleIt(sender, routeId, msgView);

		if (routeId.GetAgentId() != m_AgentId)
			// I'm not the final recipient -> packet needs to be passed further.
			MultiSendPacketFurtherThroughRouteId(packet0, routeId);
	}
	catch (std::exception& exception)
	{
		throw std::runtime_error{ OBF_STR("Failed to parse G2R packet. ") + exception.what() };
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::MultiSendPacketFurtherThroughRouteId(ByteView packet0, RouteId routeId)
{
	auto route = FindRoute(routeId);
	if (!route)
		throw std::invalid_argument{ OBF("Tried to send a packet using non-existent RouteID.") };

	if (auto channel = route->m_Channel.lock())
		LockAndSendPacket(packet0, channel);
	else
		Log({ OBF("Tried to send a packet through a dead Channel."), LogMessage::Severity::Warning });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::PostCommandToConnector(ByteView command, std::shared_ptr<DeviceBridge> senderPeripheral)
{
	auto grc = GetGatewayReturnChannel();
	if (!grc)
		throw std::runtime_error{ OBF("No GRC set while trying to send a S2G packet.") };

	auto connectorHash = InterfaceFactory::Instance().Find<AbstractPeripheral>(senderPeripheral->GetTypeNameHash())->second.m_ClousureConnectorHash;
	auto query = ProceduresS2G::DeliverToBinder::Create(RouteId{ GetAgentId(), grc->GetDid() }, FSecure::Utils::TimeSinceEpoch(), senderPeripheral->GetDid(), connectorHash, command, m_GatewayEncryptionKey);
	LockAndSendPacket(query->ComposeQueryPacket(), grc);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::SetGatewayReturnChannel(std::shared_ptr<DeviceBridge> const& gatewayReturnChannel)
{
	m_GatewayReturnChannel = gatewayReturnChannel;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::SetGatewayReturnChannel(FSecure::ByteView args)
{
	auto channel = m_Devices.Find([did = DeviceId{ args.Read<std::string>() } ](auto const& e) { auto l = e.lock(); return l ? l->GetDid() == did && l->IsChannel() : false; }).lock();
	if (!channel)
		throw std::runtime_error{ OBF("Device not found") };

	SetGatewayReturnChannel(channel);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<FSecure::C3::Core::DeviceBridge> FSecure::C3::Core::NodeRelay::GetGatewayReturnChannel() const
{
	return m_GatewayReturnChannel.lock();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<FSecure::C3::Core::DeviceBridge> FSecure::C3::Core::NodeRelay::CreateAndAttachDevice(DeviceId iid, HashT deviceNameHash, bool isNegotiationChannel, ByteView commandLine, bool negotiationClient /*= false*/)
{
	// Call the original CreateNewDevice.
	auto device = Relay::CreateAndAttachDevice(iid, deviceNameHash, isNegotiationChannel, commandLine, negotiationClient);
	if (!m_GatewayReturnChannel.lock() && !isNegotiationChannel && device->IsChannel())																			// First non-negotiation channel is automatically set as GRC.
		SetGatewayReturnChannel(device);

	return device;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::InitializeRoute()
{
	// Sanity check.
	auto grc = GetGatewayReturnChannel();
	if (!grc)
		throw std::runtime_error{ OBF("No GRC.") };

	// And post it to Neighbor through GRC.
	auto query = ProceduresN2N::InitializeRouteQuery::Create(RouteId{ GetAgentId(), grc->GetDid() }, GetBuildId(), m_GatewayEncryptionKey, m_MyEncryptionKey, grc->GetTypeNameHash(), FSecure::Utils::TimeSinceEpoch());
	LockAndSendPacket(query->ComposeQueryPacket(), grc);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::NegotiateChannel(std::shared_ptr<DeviceBridge> const& device)
{
	auto query = ProceduresN2N::ChannelIdExchangeStep1::Create(RouteId{ m_AgentId, device->GetDid()}, device->GetInputId());
	LockAndSendPacket(query->ComposeQueryPacket(), device);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::On(ProceduresN2N::InitializeRouteQuery query)
{
	// Retrieve GRC.
	auto grc = GetGatewayReturnChannel();
	if (!grc)
		throw std::runtime_error(OBF("Cannot get GRC"));


	auto queryS2G = ProceduresS2G::InitializeRouteQuery::Create(RouteId{ GetAgentId(), grc->GetDid() }, FSecure::Utils::TimeSinceEpoch(), query.GetSenderRouteId(), query.GetSenderChannel().lock()->GetDid(), query.GetQueryPacket(), m_GatewayEncryptionKey);
	LockAndSendPacket(queryS2G->ComposeQueryPacket(), grc);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::On(ProceduresS2G::InitializeRouteQuery query)
{
	throw std::logic_error{ OBF("Wrong recipient.") };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::On(ProceduresG2X::RunCommandOnAgentQuery query)
{
	ByteView queryBody = query.GetPacketBody();
	auto command = static_cast<Command>(queryBody.Read<std::underlying_type_t<Command>>());
	switch (command)
	{
	case Command::AddDevice:
	{
		auto device = RunCommandAddDevice(queryBody);
		SendNewDeviceNotification(device);
		break;
	}
	case Command::Close:
		Close();
		break;
	case Command::CreateRoute:
		CreateRoute(queryBody);
		break;
	case Command::RemoveRoute:
		RemoveRoute(queryBody);
		break;
	case Command::SetGRC:
		SetGatewayReturnChannel(queryBody);
		break;
	case Command::Ping:
		Ping(queryBody);
		break;
	default:
		throw std::runtime_error(OBF("NodeRelay received an unknown command"));
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::On(ProceduresG2X::AddRoute query)
{
	auto recipient = query.GetRecipientRouteId();
	auto [newRoute, directionDid] = ByteView{ query.GetPacketBody() }.Read<RouteId, DeviceId>();
	std::shared_ptr<DeviceBridge> bridge;
	if (recipient.GetAgentId() == GetAgentId())
	{
		auto& dir = directionDid;
		bridge = m_Devices.Find([&](auto& wp) { auto sp = wp.lock(); return sp ? sp->GetDid() == dir : false; }).lock();
		if (!bridge)
			throw std::runtime_error{OBF("Cannot find bridge.")};
	}
	else
	{
		auto route = FindRoute(recipient);
		if (!route)
			throw std::runtime_error{ OBF("Cannot find route to original recipient.") };

		bridge = route->m_Channel.lock();
		if (!bridge)
			throw std::runtime_error{ OBF("Channel to original recipient was closed.") };
	}

	AddRoute(newRoute, bridge);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::On(ProceduresG2X::RunCommandOnDeviceQuery query)
{
	ByteView queryBody = query.GetPacketBody();
	auto deviceId = DeviceId (queryBody.Read<DeviceId::UnderlyingIntegerType>());

	auto device = m_Devices.Find([deviceId](auto& wp) { auto sp = wp.lock(); return sp ? sp->GetDid() == deviceId : false; }).lock();
	if (!device)
		throw std::runtime_error{ OBF("Cannot find device.") };

	device->RunCommand(queryBody);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::On(ProceduresG2X::DeliverToBinder query)
{
	ByteView queryBody = query.GetPacketBody();
	auto deviceId = DeviceId(queryBody.Read<DeviceId::UnderlyingIntegerType>());

	auto device = m_Devices.Find([deviceId](auto& wp) { auto sp = wp.lock(); return sp ? sp->GetDid() == deviceId : false; }).lock();
	if (!device)
		throw std::runtime_error{ OBF("Cannot find device.") };

	device->OnCommandFromConnector(queryBody);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::On(ProceduresN2N::ChannelIdExchangeStep1 query)
{
	auto readView = ByteView{ query.GetQueryPacket() };
	auto newOutputId = readView.Read<ByteView>();

	auto newInputId = FSecure::Utils::GenerateRandomString(newOutputId.size());
	auto sender = query.GetSenderChannel().lock();
	if (!sender)
		throw std::runtime_error(OBF("Invalid sender channel"));

	// sanity check
	if (!sender->IsNegotiationChannel())
		throw std::runtime_error(OBF("Sender Channel is not a negotiation channel"));

	auto newDeviceId = ++m_LastResevedDeviceId;
	auto negotiatedChannelArgs = ByteVector{}.Write(newInputId, newOutputId).Concat(sender->GetChannelParameters());
	auto newChannel = CreateAndAttachDevice(newDeviceId, sender->GetTypeNameHash(), false, negotiatedChannelArgs);
	SendNewNegotiatedChannelNotification(newChannel->GetDid(), sender->GetDid(), ByteView{ newInputId }, newOutputId);
	auto x = ProceduresN2N::ChannelIdExchangeStep2::Create(RouteId(m_AgentId, newChannel->GetDid()), ByteView{ newInputId });
	LockAndSendPacket(x->ComposeQueryPacket(), newChannel);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::On(ProceduresN2N::ChannelIdExchangeStep2 query)
{
	auto readView = ByteView{ query.GetQueryPacket() };
	auto newOutputId = readView.Read<ByteView>();

	auto sender = query.GetSenderChannel().lock();

	// sanity check
	if (!sender->IsNegotiationChannel())
		throw std::runtime_error(OBF("Sender Channel is not a negotiation channel"));

	ByteVector args = sender->GetChannelParameters();
	auto hash = sender->GetTypeNameHash();
	auto newInputId = sender->GetInputId() ;
	DetachDevice(sender->GetDid());
	sender.reset();
	// Don't use sender below;

	auto permanentChannelArgs = ByteVector{}.Write(newInputId, newOutputId).Concat(args);
	auto newChannel = CreateAndAttachDevice(++m_LastResevedDeviceId, hash, false, permanentChannelArgs);

	SetGatewayReturnChannel(newChannel);
	InitializeRoute();
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<FSecure::C3::Core::DeviceBridge> FSecure::C3::Core::NodeRelay::RunCommandAddDevice(ByteView commandArgs)
{
	auto [deviceId, isNegotiable, deviceTypeHash] = commandArgs.Read<DeviceId::UnderlyingIntegerType, bool, HashT>();
	return CreateAndAttachDevice(deviceId, deviceTypeHash, isNegotiable, commandArgs);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::SendNewDeviceNotification(std::shared_ptr<FSecure::C3::Core::DeviceBridge> const& device)
{
	auto grc = GetGatewayReturnChannel();
	if (!grc)
		throw std::runtime_error(OBF("Failed to lock gateway return channel"));

	auto response = ProceduresS2G::AddDeviceResponse::Create(RouteId(m_AgentId, grc->GetDid()), FSecure::Utils::TimeSinceEpoch(), device->GetDid(), device->GetTypeNameHash(), device->IsChannel(), device->IsNegotiationChannel(), m_GatewayEncryptionKey);
	LockAndSendPacket(response->ComposeQueryPacket(), grc);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::NodeRelay::SendNewNegotiatedChannelNotification(DeviceId newDeviceId, DeviceId negotiatorId, ByteView inId, ByteView outId)
{
	auto grc = GetGatewayReturnChannel();
	if (!grc)
		throw std::runtime_error(OBF("Failed to lock gateway return channel"));

	auto response = ProceduresS2G::NewNegotiatedChannelNotification::Create(RouteId(m_AgentId, grc->GetDid()), FSecure::Utils::TimeSinceEpoch(), newDeviceId, negotiatorId, inId, outId, m_GatewayEncryptionKey);
	LockAndSendPacket(response->ComposeQueryPacket(), grc);
}

void FSecure::C3::Core::NodeRelay::Ping(FSecure::ByteView args)
{
	auto grc = GetGatewayReturnChannel();
	if (!grc)
		throw std::runtime_error(OBF("Failed to lock gateway return channel"));

	auto response = ProceduresS2G::Notification::Create(RouteId(m_AgentId, grc->GetDid()), FSecure::Utils::TimeSinceEpoch(), ByteView{}, m_GatewayEncryptionKey);
	LockAndSendPacket(response->ComposeQueryPacket(), grc);
}
