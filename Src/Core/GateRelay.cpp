#include "StdAfx.h"
#include "GateRelay.h"
#include "Profiler.h"
#include "DeviceBridge.h"
#include "Common/FSecure/Sockets/SocketsException.h"
#include "ConnectorBridge.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<FSecure::C3::Core::GateRelay> FSecure::C3::Core::GateRelay::CreateAndRun(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory,
	std::string_view apiBridgeIp, std::uint16_t apiBrigdePort, FSecure::Crypto::SignatureKeys const& signatures, FSecure::Crypto::SymmetricKey const& broadcastKey,
	FSecure::C3::BuildId buildId, std::filesystem::path snapshotPath, FSecure::C3::AgentId agentId /*= FSecure::C3::AgentId::GenerateRandom()*/, std::string name /*= ""*/)
{
	// Create GateRelay.
	auto gateNode = std::shared_ptr<GateRelay>{ new GateRelay(callbackOnLog, interfaceFactory, apiBridgeIp, apiBrigdePort, signatures, broadcastKey, buildId, std::move(snapshotPath), agentId) };
	gateNode->m_Profiler->Initialize(std::move(name), gateNode);
	// Start API bridge.
	gateNode->Log({ "Starting API bridge on " + std::string{ apiBridgeIp } + ":" + std::to_string(apiBrigdePort), FSecure::C3::LogMessage::Severity::Information });
	std::thread([self = gateNode, controllerIp = std::string{ apiBridgeIp }, apiBrigdePort]() mutable { self->RunApiBrige(controllerIp, apiBrigdePort); }).detach();

	// Done.
	return gateNode;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::GateRelay::GateRelay(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory, std::string_view selfIp, std::uint16_t apiBrigdePort,
	FSecure::Crypto::SignatureKeys const& signatures, FSecure::Crypto::SymmetricKey const& broadcastKey, FSecure::C3::BuildId buildId, std::filesystem::path snapshotPath, FSecure::C3::AgentId agentId)
	: Relay(callbackOnLog, interfaceFactory, Crypto::ConvertToKey(signatures.first), broadcastKey, buildId, agentId)
	, m_AuthenticationKey{ Crypto::ConvertToKey(signatures.second) }
	, m_Signature{ signatures.first }
	, m_Profiler(std::make_shared<Profiler>(std::move(snapshotPath)))
{
	Log({ "Gateway launched.", FSecure::C3::LogMessage::Severity::Information });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool FSecure::C3::Core::GateRelay::IsAgentBanned(AgentId agentId)
{
	if (auto agent = m_Profiler->Get().m_Gateway.m_Agents.Find(agentId))
		return agent->m_IsBanned;

	return __super::IsAgentBanned(agentId);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::OnProtocolS2G(ByteView packet0, std::shared_ptr<DeviceBridge> sender)
{
	try
	{
		auto decrypted = FSecure::Crypto::DecryptFromAnonymous(packet0.SubString(1), m_AuthenticationKey, m_DecryptionKey);
		auto [procedure, rid, timestamp] = ByteView{ decrypted }.Read<ProceduresUnderlyingType, RouteId, int32_t>();
		if (!m_Profiler->Get().m_Gateway.ConnectionExist(rid.GetAgentId()))
			throw std::runtime_error{ "S2G packet received from not connected source." };

		ProceduresS2G::RequestHandler::ParseRequestAndHandleIt(sender, procedure, rid, timestamp, packet0.SubString(1));
	}
	catch (std::exception& exception)
	{
		throw std::runtime_error{ "Failed to parse S2G packet. "s + exception.what() };
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::OnProtocolG2A(ByteView packet0, std::shared_ptr<DeviceBridge> sender)
{
	throw std::runtime_error{ "G2A packet received from Channel: " + sender->GetDid().ToString() + "." };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::OnProtocolG2R(ByteView packet0, std::shared_ptr<DeviceBridge> sender)
{
	throw std::runtime_error{ "G2R packet received from Channel: " + sender->GetDid().ToString() + "." };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::PostCommandToConnector(ByteView command, std::shared_ptr<DeviceBridge> senderPeripheral)
{
	auto connectorHash = InterfaceFactory::Instance().Find<AbstractPeripheral>(senderPeripheral->GetTypeNameHash())->second.m_ClousureConnectorHash;
	auto connector = m_Connectors.Find([&](auto const& e) { return e->GetNameHash() == connectorHash; });
	if (!connector)
		throw std::runtime_error{ "Connector not found" };

	connector->OnCommandFromBinder(RouteId{ GetAgentId(), senderPeripheral->GetDid() }.ToByteVector(), command);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::PostCommandToPeripheral(ByteView command, RouteId routeId)
{
 	// Check if Peripheral is attached to Gateway.
	if (routeId.GetAgentId() == GetAgentId())
	{
 		if (auto peripheral = m_Devices.Find([&](auto const& e) {auto sp = e.lock(); return sp &&  sp->GetDid() == routeId.GetInterfaceId(); }).lock(); peripheral)
 			return peripheral->OnCommandFromConnector(command);
 		else
 			throw std::runtime_error{ "Couldn't find Gateway's recipient Peripheral." };
	}

	auto route = FindRoute(routeId.GetAgentId());
	if (!route)
		throw std::runtime_error{ "Unknown route." };

	auto device = route->m_Channel.lock();
	if (!device)
		throw std::runtime_error{ "Route was unexpectedly closed." };

	auto agent = m_Profiler->Get().m_Gateway.m_Agents.Find(routeId.GetAgentId());
	if (!agent)
		throw std::runtime_error{ "Unknown agent." };

	auto query = ProceduresG2X::DeliverToBinder::Create(route->m_RouteId, m_Signature, agent->m_EncryptionKey, m_DecryptionKey, routeId.GetInterfaceId(), command);
	LockAndSendPacket(query->ComposeQueryPacket(), device);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::RunApiBrige(std::string_view apiBrigdeIp, std::uint16_t apiBrigdePort) noexcept
{
	std::chrono::seconds reconnectWait = 0s;
	while (m_IsAlive)
	{
		try
		{
			DuplexConnection connection(apiBrigdeIp, apiBrigdePort);
			connection.StartSending();

			auto clientKeys = Crypto::GenerateExchangeKeys();
			connection.Send(clientKeys.second.ToByteVector());

			auto firstMessage = connection.Receive();
			Crypto::ExchangePublicKey serverPublicKey = firstMessage;
			m_SessionKeys = Crypto::GenerateClientSessionKeys(clientKeys, serverPublicKey);

			// Send initial packet
			connection.Send(ByteView
				{
					Crypto::Encrypt(ByteView{json
					{
						{ "messageType", "GetCapability" },
						{ "messageData", m_Profiler->Get().m_Gateway.GetCapability() }
					}.dump()} ,m_SessionKeys.second)
				});

			// Keep started messageHandlers to make sure that connection outlives them
			std::list<std::future<void>> messageHandlers;
			connection.StartReceiving([self = std::static_pointer_cast<GateRelay>(shared_from_this()), &connection, &messageHandlers](ByteVector encryptedMessagePacket)
			{
				messageHandlers.emplace_back(std::async(std::launch::async, [&connection, &self, encryptedMessagePacket = std::move(encryptedMessagePacket)]()
					{
						try
						{
							auto decrypted = Crypto::Decrypt(encryptedMessagePacket, self->m_SessionKeys.first);
							ByteView messagePacket = decrypted;
							self->Log({ "Received message: " + std::string{messagePacket} , FSecure::C3::LogMessage::Severity::DebugInformation });
							auto response = self->HandleMessage(json::parse(std::string{ messagePacket }));
							if (!response.is_null())
								connection.Send(ByteView{ Crypto::Encrypt(ByteView{response.dump()}, self->m_SessionKeys.second) });
						}
						catch (std::exception& exception)
						{
							self->Log({ "Caught an exception while processing message from Controller. "s + exception.what(), FSecure::C3::LogMessage::Severity::Error });
						}
					}
				));

				// remove finished actions
				messageHandlers.remove_if( [](std::future<void> const& t)
				{
					return t.wait_for(1ns) == std::future_status::ready;
				});
			});

			Log({ "API bridge connection established on " + std::string{apiBrigdeIp} +':' + std::to_string(apiBrigdePort), FSecure::C3::LogMessage::Severity::Information });
			reconnectWait = 0s;
			// Enter main loop.
			auto sp = m_Profiler->GetSnapshotProxy();
			while (m_IsAlive && connection.IsSending())
			{
				// Read socket.
				std::this_thread::sleep_for(300ms);
				if (sp.CheckUpdates())
				{
					try
					{
						connection.Send(Crypto::Encrypt(ByteView{ json{ { "messageType", "GetProfile" }, { "messageData", sp.GetSnapshot()}}.dump() }, m_SessionKeys.second));
					}
					catch (std::exception& exception)
					{
						Log({ "Caught an exception while sending Profile. "s + exception.what(), FSecure::C3::LogMessage::Severity::Error });
						break;
					}
				}
			}
		}
		catch (SocketsException& exception)
		{
			Log({ "Connection to Controller failed. "s + exception.what() + ". Reconnect after " + std::to_string(reconnectWait.count()) + "s", FSecure::C3::LogMessage::Severity::Error });
			std::this_thread::sleep_for(reconnectWait);
			reconnectWait += 10s;
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::TurnOnConnector(HashT connectorNameHash, ByteView commandLine)
{
	// Find the right factory and turn Connector on.
	if (auto connectorData = InterfaceFactory::Instance().GetInterfaceData<AbstractConnector>(connectorNameHash); !connectorData)
		throw std::runtime_error{ "Couldn't find factory for Device of hash '" + std::to_string(connectorNameHash) + "'." };
	else
	{
		// Check if Connector is already on.
		if (m_Connectors.Find([&connectorNameHash](std::shared_ptr<ConnectorBridge> c)
			{
				try
				{
					return c->GetNameHash() == connectorNameHash;
				}
				catch (...)
				{
					return false;
				}
			}))
				throw std::invalid_argument{ "Connector of hash '" + std::to_string(connectorNameHash) + "' is already turned on." };

		// Create and add Connector.
		auto connector = std::make_shared<ConnectorBridge>(std::static_pointer_cast<GateRelay>(shared_from_this()), connectorData->m_Builder(commandLine), connectorData->m_Name, connectorNameHash);
		connector->OnAttach();
		m_Connectors.Add(connector);

		// Let the Profiler know that there's a new Connector turned on.
		m_Profiler->Get().m_Gateway.ReTurnOnConnector(connectorNameHash, connector);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::TurnOffConnector(HashT connectorNameHash)
{
	m_Profiler->Get().m_Gateway.ReTurnOffConnector(connectorNameHash);
	m_Connectors.Remove([&connectorNameHash](std::shared_ptr<ConnectorBridge> c)
		{
			if (c->GetNameHash() == connectorNameHash)
			{
				c->Detach();
				return true;
			}
			return false;
		});
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<FSecure::C3::Core::ConnectorBridge> FSecure::C3::Core::GateRelay::GetConnector(HashT connectorNameHash)
{
	return m_Connectors.Find([&](auto& e) { return e->GetNameHash() == connectorNameHash; });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::Close()
{
	CloseDevicesAndConnectors();
	m_IsAlive = false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<FSecure::C3::Core::DeviceBridge> FSecure::C3::Core::GateRelay::CreateAndAttachDevice(DeviceId iid, HashT deviceNameHash, bool isNegotiationChannel, ByteView commandLine, bool negotiationClient /*= false*/)
{
	// Call the original CreateNewDevice.
	auto device = Relay::CreateAndAttachDevice(iid, deviceNameHash, isNegotiationChannel, commandLine, negotiationClient);

	auto profile = m_Profiler->Get();
	// Let the Profiler know that there's a new Device in the Network.
	if (device->IsChannel())
		profile.m_Gateway.ReAddChannel(device->GetDid(), device->GetTypeNameHash(), false, device->IsNegotiationChannel());
	else
		profile.m_Gateway.ReAddPeripheral(device->GetDid(), device->GetTypeNameHash());

	return device;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::DetachDevice(DeviceId const& iidOfDeviceToDetach)
{
	if (FindDevice(iidOfDeviceToDetach)->IsChannel())
		m_Profiler->Get().m_Gateway.ReDeleteChannel(iidOfDeviceToDetach);
	else
		m_Profiler->Get().m_Gateway.ReDeletePeripheral(iidOfDeviceToDetach);

	Relay::DetachDevice(iidOfDeviceToDetach);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::On(ProceduresN2N::InitializeRouteQuery query)
{
	auto decryptedPacket = query.GetQueryPacket(this->m_AuthenticationKey, this->m_DecryptionKey);
	auto readView = ByteView{ decryptedPacket };
	auto newRelayBuildId = BuildId{ readView.Read<BuildId::UnderlyingIntegerType>() };
	// todo prepending fixed-size key with 4 byte length is unnecessary, (remember to change writing, not only reading)
	auto newRelayPublicKey = Crypto::PublicKey{ readView.Read<ByteView>() };
	auto hash = readView.Read<HashT>();
	auto lastSeen = readView.Read<int32_t>();
	HostInfo hostInfo(readView.Read<ByteView>());

	auto receivedFrom = query.GetSenderChannel().lock();
	if (!receivedFrom)
		return; // TODO signalize error

	auto const& returnChannelRoute = query.GetSenderRouteId();
	this->AddRoute(returnChannelRoute, receivedFrom);
	m_Profiler->Get().m_Gateway.ReAddRoute(returnChannelRoute, receivedFrom->GetDid(), true);
	m_Profiler->Get().m_Gateway.ReAddAgent(returnChannelRoute.GetAgentId(), newRelayBuildId, newRelayPublicKey, false, lastSeen, std::move(hostInfo)); // TODO check if is banned
	m_Profiler->Get().m_Gateway.m_Agents.Find(returnChannelRoute.GetAgentId())->ReAddChannel(returnChannelRoute.GetInterfaceId(), hash, true);
	m_Profiler->Get().m_Gateway.ConditionalUpdateChannelParameters({ GetAgentId(), receivedFrom->GetDid() });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::On(ProceduresS2G::InitializeRouteQuery query)
{
	// whole message.
	auto decryptedPacket = query.GetQueryPacket(m_AuthenticationKey, m_DecryptionKey);
	auto readView = ByteView{ decryptedPacket };

	// part of message created by parent Node
	auto [procedureID, parentRid, timestamp, childRid, childSideDid] = readView.Read<ProceduresUnderlyingType, RouteId, int32_t, RouteId, DeviceId>();

	// part of message from new relay. encrypted once again because it was blob for parent relay.
	auto childPacket = Crypto::DecryptFromAnonymous(readView, m_AuthenticationKey, m_DecryptionKey);
	readView = ByteView{ childPacket };

	auto newRelayBuildId = BuildId{ readView.Read<BuildId::UnderlyingIntegerType>() }; // todo blocking
	auto newRelayPublicKey = Crypto::PublicKey{ readView.Read<ByteView>() };
	auto hash = readView.Read<HashT>();
	auto lastSeen = readView.Read<int32_t>();
	HostInfo hostInfo(readView.Read<ByteView>());

	auto receivedFrom = query.GetSenderChannel().lock();
	if (!receivedFrom)
		return; // TODO signalize error

	//Add route.
	AddRoute(childRid, receivedFrom);

	//update profiler
	m_Profiler->Get().m_Gateway.ReAddRemoteAgent(childRid, newRelayBuildId, newRelayPublicKey, RouteId{ parentRid.GetAgentId(), childSideDid }, hash, lastSeen, hostInfo);
	m_Profiler->Get().m_Gateway.UpdateRouteTimestamps(parentRid.GetAgentId(), timestamp);
	m_Profiler->Get().m_Gateway.ConditionalUpdateChannelParameters({ parentRid.GetAgentId(), childSideDid });

	//send update message across route.
	auto&& packet = ProceduresG2X::AddRoute::Create(parentRid, m_Signature, ByteVector::Create(childRid,childSideDid));
	LockAndSendPacket(packet->ComposeQueryPacket(), receivedFrom);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::On(ProceduresS2G::DeliverToBinder query)
{
	// whole message.
	auto decryptedPacket = query.GetQueryPacket(m_AuthenticationKey, m_DecryptionKey);
	auto readView = ByteView{ decryptedPacket };

	auto unusedProtocolId = readView.Read<int8_t>();
	auto senderRid = readView.Read<RouteId>();
	auto timestamp = readView.Read<int32_t>();
	auto deviceId = readView.Read<DeviceId>();
	auto connectorHash = readView.Read<HashT>();

	auto connector = m_Connectors.Find([&](auto const& e){ return e->GetNameHash() == connectorHash; });
	if (!connector)
		throw std::runtime_error{ "Connector not found" };

	auto binder = RouteId{ senderRid.GetAgentId(), deviceId }.ToByteVector();
	connector->OnCommandFromBinder(binder, readView);

	m_Profiler->Get().m_Gateway.UpdateRouteTimestamps(senderRid.GetAgentId(), timestamp);

	// part storing first message from beacon for gateway restart. This must be done here, as connectors knows nothing about profiler.
	auto agent = m_Profiler->Get().m_Gateway.m_Agents.Find(senderRid.GetAgentId());
	if (!agent)
		return;

	auto peripheral = agent->m_Peripherals.Find(deviceId);
	if (!peripheral || peripheral->m_StartupArguments.is_null())
		return;

	if (!peripheral->m_StartupArguments["FirstResponse"].is_null())
		return;

	peripheral->m_StartupArguments["FirstResponse"] = base64::encode(readView);
	peripheral->m_StartupArguments["Binder"] = base64::encode(binder);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::On(ProceduresS2G::AddDeviceResponse response)
{
	auto decryptedPacket = response.GetQueryPacket(m_AuthenticationKey, m_DecryptionKey);
	auto readView = ByteView{ decryptedPacket };
	auto [unsusedProcedureNo, unusedSenderRouteId, timestamp, deviceId, deviceTypeHash, flags] = readView.Read<ProceduresUnderlyingType, RouteId, int32_t, DeviceId, HashT, std::uint8_t>();
	bool isChannel = flags & 1;
	bool isNegotiationChannel = flags & (1 << 1);

	auto agent = m_Profiler->Get().m_Gateway.m_Agents.Find(response.GetSenderRouteId().GetAgentId());
	if (!agent)
		throw std::runtime_error("Received response from agent which is not tracked. [AgentId] = " + response.GetSenderRouteId().GetAgentId().ToString());

	if (isChannel)
		agent->ReAddChannel(deviceId, deviceTypeHash, false, isNegotiationChannel);
	else
		agent->ReAddPeripheral(deviceId, deviceTypeHash);

	m_Profiler->Get().m_Gateway.UpdateRouteTimestamps(response.GetSenderRouteId().GetAgentId(), timestamp);
	m_Profiler->Get().m_Gateway.ConditionalUpdateChannelParameters({ response.GetSenderRouteId().GetAgentId(), deviceId });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::On(ProceduresN2N::ChannelIdExchangeStep1 query)
{
	auto readView = ByteView{ query.GetQueryPacket() };
	auto newOutputId = readView.Read<ByteView>();

	auto newInputId = FSecure::Utils::GenerateRandomString(newOutputId.size());
	auto sender = query.GetSenderChannel().lock();
	if (!sender)
		throw std::runtime_error("Invalid sender channel");

	// sanity check
	if (!sender->IsNegotiationChannel())
		throw std::runtime_error("Sender Channel is not a negotiation channel");
	auto negotiatedChannelArgs = ByteVector{}.Write(newInputId, newOutputId).Concat(sender->GetChannelParameters());
	auto newDeviceId = ++(m_Profiler->Get().m_Gateway.m_LastDeviceId);
	auto newChannel = CreateAndAttachDevice(newDeviceId, sender->GetTypeNameHash(), false, negotiatedChannelArgs);

	// write arguments to profiler, bad code
	m_Profiler->Get().m_Gateway.UpdateFromNegotiationChannel(sender->GetDid(), newDeviceId, newInputId, ByteView{ newOutputId });

	// send response
	auto x = ProceduresN2N::ChannelIdExchangeStep2::Create(RouteId(m_AgentId, newChannel->GetDid()), ByteView{ newInputId });
	LockAndSendPacket(x->ComposeQueryPacket(), newChannel);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::On(ProceduresN2N::ChannelIdExchangeStep2 query)
{
	throw std::logic_error("Gateway should never receive the second step message of channel Id negotiation");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::On(ProceduresS2G::NewNegotiatedChannelNotification query)
{
	auto decryptedPacket = query.GetQueryPacket(m_AuthenticationKey, m_DecryptionKey);
	auto readView = ByteView{ decryptedPacket };
	auto [unsusedProcedureNo, unusedSenderRouteId, timestamp, newDeviceId, negotiatorId, inId, outId] = readView.Read<ProceduresUnderlyingType, RouteId, int32_t, DeviceId::UnderlyingIntegerType, DeviceId, std::string, std::string>();

	auto agent = m_Profiler->Get().m_Gateway.m_Agents.Find(query.GetSenderRouteId().GetAgentId());
	if (!agent)
		throw std::runtime_error("Received response from agent which is not tracked. [AgentId] = " + query.GetSenderRouteId().GetAgentId().ToString());

	auto negotiator = agent->m_Channels.Find(negotiatorId);
	if (!negotiator)
		throw std::runtime_error("Received new negotiated channel notification, but unknown with unknown Negotiator DeviceId" + negotiatorId.ToString());

	agent->ReAddChannel(newDeviceId, negotiator->m_TypeHash, false, false);
	agent->UpdateFromNegotiationChannel(negotiatorId, newDeviceId, inId, outId);

	m_Profiler->Get().m_Gateway.UpdateRouteTimestamps(query.GetSenderRouteId().GetAgentId(), timestamp);
	m_Profiler->Get().m_Gateway.ConditionalUpdateChannelParameters({ query.GetSenderRouteId().GetAgentId(), DeviceId{newDeviceId} });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::On(ProceduresS2G::Notification query)
{
	auto decryptedPacket = query.GetQueryPacket(m_AuthenticationKey, m_DecryptionKey);
	auto readView = ByteView{ decryptedPacket };
	auto [unsusedProcedureNo, unusedSenderRouteId, timestamp, blob] = readView.Read<ProceduresUnderlyingType, RouteId, int32_t, ByteView>();
	// blob has not defined structure. Currently Notification is used as ping response.

	auto agent = m_Profiler->Get().m_Gateway.m_Agents.Find(query.GetSenderRouteId().GetAgentId());
	if (!agent)
		throw std::runtime_error("Received response from agent which is not tracked. [AgentId] = " + query.GetSenderRouteId().GetAgentId().ToString());

	m_Profiler->Get().m_Gateway.UpdateRouteTimestamps(query.GetSenderRouteId().GetAgentId(), timestamp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
nlohmann::json FSecure::C3::Core::GateRelay::HandleMessage(nlohmann::json const& message)
{
	auto messageType = message.at("MessageType").get<std::string>();
	auto sequenceNumber = message.value("SequenceNumber", 0ul);
	auto const& messageData = message.at("MessageData");

	json commandResponse;
	std::optional<std::string> error;
	try
	{
		if (messageType == "Action")
		{
			m_Profiler->HandleActionsPacket(ByteView{ messageData.dump() });
			return {};
		}
		else if (messageType == "NewBuild")
		{
			commandResponse = m_Profiler->HandleNewBuildMessage(messageData);
		}
		else if (messageType == "Error")
		{
			Log({ "Controller error: " + messageData.at("Message").get<std::string>(), LogMessage::Severity::Error });
		}
	}
	catch (std::exception& e)
	{
		Log({"HandleMessage failed: Seq: "s + std::to_string(sequenceNumber) + ". Reason: " + e.what(), LogMessage::Severity::Warning});
		error = e.what();
	}

	if (sequenceNumber == 0)
		return {};

	json fullResponse
	{
		{"MessageType", messageType},
		{"SequenceNumber", sequenceNumber},
		{"MessageData", commandResponse },
	};

	if (error)
		fullResponse["Error"] = *error;

	return fullResponse;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::CloseDevicesAndConnectors()
{
	Relay::Close();

	m_Connectors.For([](auto c)
	{
		c->Detach();
		return true;
	});

	m_Connectors.Clear();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::GateRelay::Reset()
{
	CloseDevicesAndConnectors();
	RemoveAllRoutes();
}
