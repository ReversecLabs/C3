#include "StdAfx.h"
#include "Profiler.h"
#include "NodeRelay.h"
#include "GateRelay.h"
#include "ConnectorBridge.h"
#include "DeviceBridge.h"
#include "Common/FSecure/CppTools/Utils.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::mutex FSecure::C3::Core::Profiler::Profile::m_Mutex;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Profiler(std::filesystem::path snapshotPath) : m_SnapshotPath(std::move(snapshotPath))
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Initialize(std::string name, std::shared_ptr<GateRelay> gateway)
{
	m_Gateway = Gateway{ shared_from_this(), name, gateway };
	for (auto&& e : m_Gateway->m_Gateway.lock()->m_InterfaceFactory.GetMap<AbstractPeripheral>())
		m_BindersMappings.emplace_back(e.first, e.second.m_ClousureConnectorHash);

	RestoreFromSnapshot();
	std::thread(&Profiler::DumpSnapshots, this).detach();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::HandleActionsPacket(ByteView actionsPacket)
{
	std::scoped_lock lock(m_AccessMutex);

	try
	{
		auto actions = json::parse(std::string{ actionsPacket });
		auto jActions = actions.find("Command");
		if (jActions == actions.end())
			throw std::runtime_error{ "Command object is missing" };

		(*jActions)["ByteForm"] = base64::encode(TranslateCommand(*jActions));

		// Helper lambda that read particular element from actions JSON.
		auto ReadJsonElement = [&actions](std::string_view elementName)
		{
			auto element = actions.find(elementName);
			if (element != actions.end())
				return element;

			throw std::runtime_error{ std::string{ elementName } +" is not specified." };
		};

		// Parse AgentId.
		if (auto relayAgentId = ReadJsonElement("relayAgentId"); relayAgentId->is_null())
			m_Gateway->ParseAndRunCommand(actions);
		else if (auto agent = m_Gateway->m_Agents.Find(relayAgentId->get<std::string>()))
			agent->ParseAndRunCommand(actions);
		else
			throw std::runtime_error{ "Unknown AgentId." };
	}
	catch (std::exception& exception)
	{
		if (auto gateway = m_Gateway->m_Gateway.lock())
			gateway->Log({ "Caught an exception while parsing Action. "s + exception.what(), FSecure::C3::LogMessage::Severity::Error});
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Profile FSecure::C3::Core::Profiler::Get()
{
	return Profile{ *m_Gateway };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
uint32_t FSecure::C3::Core::Profiler::GetBinderTo(uint32_t id)
{
	for (auto&& e : m_BindersMappings)
		if (e.first == id)
			return e.second;
		else if (e.second == id)
			return e.first;

	return 0u;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Core::Profiler::TranslateCommand(json const& command)
{
	return ByteVector::Create(command.at("id").get<uint16_t>()).Concat(TranslateArguments(command.at("arguments")));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Core::Profiler::TranslateArguments(json const& arguments)
{
	ByteVector ret;
	auto translate = [&ret](auto arg) { ret.Concat(Translate(arg.at("type"), arg.at("value"))); };
	for (auto argument : arguments)
	{
		if (!argument.is_array())
			translate(argument);
		else
			for (auto const subargument : argument)
				translate(subargument);
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Core::Profiler::TranslateStartupCommand(json const& jcommand)
{
	auto commandId = jcommand.at("id").get<std::uint16_t>();
	auto const& createCommands = m_Gateway->m_CreateCommands;
	auto command = std::find_if(createCommands.cbegin(), createCommands.cend(), [commandId](Gateway::CreateCommand const& cc) { return cc.m_IsDevice && cc.m_Id == commandId; });

	// this function will only support create commands
	if (command == createCommands.cend() || !command->m_IsDevice)
		throw std::logic_error{ "Failed to find a create command" };

	return ByteVector::Create(command->m_IsNegotiableChannel, command->m_Hash).Concat(TranslateArguments(jcommand.at("arguments")));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Core::Profiler::Translate(std::string const& type, json::value_type const& value)
{
	if (type == "uint8")
		return ByteVector{}.Write(value.is_string() ? FSecure::Utils::SafeCast<uint8_t>(std::stoull(value.get<std::string>())) : value.get<uint8_t>());
	if (type == "uint16")
		return ByteVector{}.Write(value.is_string() ? FSecure::Utils::SafeCast<uint16_t>(std::stoull(value.get<std::string>())) : value.get<uint16_t>());
	if (type == "uint32")
		return ByteVector{}.Write(value.is_string() ? FSecure::Utils::SafeCast<uint32_t>(std::stoull(value.get<std::string>())) : value.get<uint32_t>());
	if (type == "uint64")
		return ByteVector{}.Write(value.is_string() ? FSecure::Utils::SafeCast<uint64_t>(std::stoull(value.get<std::string>())) : value.get<uint64_t>());
	if (type == "int8")
		return ByteVector{}.Write(value.is_string() ? FSecure::Utils::SafeCast<int8_t>(std::stoll(value.get<std::string>())) : value.get<int8_t>());
	if (type == "int16")
		return ByteVector{}.Write(value.is_string() ? FSecure::Utils::SafeCast<int16_t>(std::stoll(value.get<std::string>())) : value.get<int16_t>());
	if (type == "int32")
		return ByteVector{}.Write(value.is_string() ? FSecure::Utils::SafeCast<int32_t>(std::stoll(value.get<std::string>())) : value.get<int32_t>());
	if (type == "int64")
		return ByteVector{}.Write(value.is_string() ? FSecure::Utils::SafeCast<int64_t>(std::stoll(value.get<std::string>())) : value.get<int64_t>());
	if (type == "float")
		return ByteVector{}.Write(value.is_string() ? std::stof(value.get<std::string>()) : value.get<float>());
	if (type == "boolean")
		return ByteVector{}.Write(value.get<bool>());
	if (type == "string" || type == "ip")
		return ByteVector{}.Write(value.get<std::string>());
	if (type == "binary")
		return ByteVector{}.Write(base64::decode<ByteVector>(value.get<std::string>()));

	throw std::invalid_argument{ "Unrecognized argument type: " + type };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::DumpSnapshots()
{
	auto sp = GetSnapshotProxy();
	while (true)
	{
		if (sp.CheckUpdates())
		{
			const auto snapshotTmpPath = std::filesystem::path(m_SnapshotPath).replace_extension(".tmp");
			{
				std::ofstream snapshotTmp{ snapshotTmpPath };
				snapshotTmp << sp.GetSnapshot().dump() << std::endl;
			}
			std::filesystem::rename(snapshotTmpPath, m_SnapshotPath);
		}
		std::this_thread::sleep_for(1s);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::RestoreFromSnapshot()
{
	json snapshot;
	// get snapshot
	{
		auto ifile = std::ifstream{ m_SnapshotPath };
		auto str = std::string((std::istreambuf_iterator<char>(ifile)), std::istreambuf_iterator<char>());
		if (str.empty())
			return;
		snapshot = json::parse(str);
	}

	// restore gateway.
	{
		for (auto&& b : snapshot["_RegisteredBuilds"])
		{
			m_Gateway->AddAgentBuild
			(
				b.at("_bid").get<BuildId::UnderlyingIntegerType>(),
				BuildProperties
				{
					b.at("_x64").get<bool>(),
					b.at("_ban").get<bool>(),
					b.at("_startCmd"),
				}
			);
		}

		for (auto&& channel : snapshot["channels"])
		{
			auto gateRelay = Get().m_Gateway.m_Gateway.lock();
			if (!gateRelay)
				throw std::logic_error("Parent GateRelay cannot be locked");

			auto byteForm = base64::decode<ByteVector>(channel["startupCommand"]["ByteForm"].get<std::string>());
			auto readView = ByteView{ byteForm };
			readView.remove_prefix(sizeof(uint16_t)); // remove number of command
			auto did = DeviceId{ channel["iId"].get<std::string>() };
			auto device = gateRelay->CreateAndAttachDevice
			(
				did,
				channel["type"].get<HashT>(),
				channel["isNegotiationChannel"].get<bool>(),
				readView
			);

			auto jitter = std::pair{ FSecure::Utils::ToMilliseconds(channel["jitter"][0].get<float>()), FSecure::Utils::ToMilliseconds(channel["jitter"][1].get<float>()) };
			device->SetUpdateDelay(jitter.first, jitter.second);
			auto profile = Get(); // we need to take profile each time, as it is also taken in CreateAndAttachDevice and that would lead to deadlock.
			auto channelProfile = profile.m_Gateway.m_Channels.Find(did);
			channelProfile->m_StartupArguments = channel["startupCommand"];
			channelProfile->m_Jitter = jitter;
		}

		for (auto&& connector : snapshot["connectors"])
		{
			auto gateRelay = Get().m_Gateway.m_Gateway.lock();
			if (!gateRelay)
				throw std::logic_error("Parent GateRelay cannot be locked");

			auto byteForm = base64::decode<ByteVector>(connector["startupCommand"]["ByteForm"].get<std::string>());
			auto readView = ByteView{ byteForm };
			readView.remove_prefix(sizeof(uint16_t)); // remove number of command
			auto did = connector["type"].get<HashT>();
			gateRelay->TurnOnConnector
			(
				did,
				readView
			);

			auto profile = Get(); // we need to take profile each time, as it is also taken in CreateAndAttachDevice and that would lead to deadlock.
			auto connectorProfile = profile.m_Gateway.m_Connectors.Find(did);
			connectorProfile->m_StartupArguments = connector["startupCommand"];
		};
	}

	// restore agents
	{
		auto profile = Get();

		for (auto&& route : snapshot["routes"])
			profile.m_Gateway.ReAddRoute(RouteId(route["destinationAgent"].get<std::string>(), route["receivingInterface"].get<std::string>()), route["outgoingInterface"].get<std::string>(), route["isNeighbour"].get<bool>());

		for (auto&& relay : snapshot["relays"])
		{
			auto agent = profile.m_Gateway.ReAddAgent
			(
				relay["agentId"].get<std::string>(),
				relay["buildId"].get<std::string>(),
				base64::decode<ByteVector>(relay["publicKey"].get<std::string>()),
				false,
				relay["timestamp"].get<int32_t>(),
				HostInfo(relay["hostInfo"])
			);

			agent->m_LastDeviceId = relay["_LastDeviceId"].get<DeviceId::UnderlyingIntegerType>();

			for (auto&& channel : relay["channels"])
			{
				auto device = agent->ReAddChannel(channel["iId"].get<std::string>(), channel["type"].get<HashT>(), channel["isReturnChannel"].get<bool>(), channel["isNegotiationChannel"].get<bool>());
				device->m_StartupArguments = channel["startupCommand"];
				device->m_Jitter = std::pair{ FSecure::Utils::ToMilliseconds(channel["jitter"][0].get<float>()), FSecure::Utils::ToMilliseconds(channel["jitter"][1].get<float>()) };
			}
			for (auto&& peripheral : relay["peripherals"])
			{
				auto device = agent->ReAddPeripheral(peripheral["iId"].get<std::string>(), peripheral["type"].get<HashT>());
				device->m_StartupArguments = peripheral["startupCommand"];
				device->m_Jitter = std::pair{ FSecure::Utils::ToMilliseconds(peripheral["jitter"][0].get<float>()), FSecure::Utils::ToMilliseconds(peripheral["jitter"][1].get<float>()) };
			}
			for (auto&& route : relay["routes"])
				agent->ReAddRoute(RouteId(route["destinationAgent"].get<std::string>(), route["receivingInterface"].get<std::string>()), route["outgoingInterface"].get<std::string>(), route["isNeighbour"].get<bool>());
		}
	}

	// Restore real routing table
	{
		auto profile = Get();
		auto gateRelay = profile.m_Gateway.m_Gateway.lock();
		if (!gateRelay)
			throw std::logic_error("Parent GateRelay cannot be locked");
		auto const& routes = profile.m_Gateway.m_Routes.GetUnderlyingContainer();
		for (auto const& route : routes)
		{
			auto outgoingDevice = gateRelay->FindDevice(route.m_OutgoingDevice);
			if (!outgoingDevice)
				throw std::logic_error("Outgoing device cannot be locked");

			gateRelay->AddRoute(route.m_Id, outgoingDevice);
		}

		profile.m_Gateway.m_LastDeviceId = snapshot["_LastDeviceId"].get<DeviceId::UnderlyingIntegerType>();
	}


	// restore connections in connector. It must be last step in the chain.
	{
		auto gateway = m_Gateway->m_Gateway.lock();
		if (!gateway)
			return;

		for (auto&& relay : snapshot["relays"])
		{
			auto profile = Get();
			for (auto&& peripheral : relay["peripherals"])
			{
				auto connectorHash = GetBinderTo(peripheral["type"].get<HashT>());
				auto connector = gateway->m_Connectors.Find([&](auto const& e) { return e->GetNameHash() == connectorHash; });
				if (!connector)
					continue;

				auto route = gateway->FindRoute(AgentId{ relay["agentId"].get<std::string>() });
				if (!route)
					continue;

				auto creationCommand = base64::decode<ByteVector>(peripheral["startupCommand"]["ByteForm"].get<std::string>());
				auto readView = ByteView{ creationCommand };
				auto connectionId = ByteVector::Create(RouteId{ route->m_RouteId.GetAgentId(),  DeviceId{ peripheral["iId"].get<std::string>() } });
				readView.remove_prefix(sizeof(uint16_t)); // remove command id
				connector->PeripheralCreationCommand(connectionId, readView); // throw away the response.
				connector->OnCommandFromBinder(connectionId, base64::decode<ByteVector>(peripheral["startupCommand"]["FirstResponse"].get<std::string>()));
			}
		}
	}

	// Gateway peripherals will not be restored. Supporting this case is not important, and they would need new staging to be done in this function. Might be added in the future.
	//for (auto&& peripheral : snapshot["peripherals"])
	//{
	//	auto gateRelay = Get().m_Gateway.m_Gateway.lock();
	//	if (!gateRelay)
	//		throw std::logic_error("Parent GateRelay cannot be locked");

	//	auto byteForm = base64::decode<ByteVector>(peripheral["startupCommand"]["ByteForm"].get<std::string>());
	//	auto readView = ByteView{ byteForm };
	//	readView.remove_prefix(sizeof(uint16_t)); // remove number of command
	//	auto did = DeviceId{ peripheral["iId"].get<std::string>() };
	//	gateRelay->CreateAndAttachDevice
	//	(
	//		did,
	//		peripheral["type"].get<HashT>(),
	//		false,
	//		readView
	//	);

	//	auto profile = Get(); // we need to take profile each time, as it is also taken in CreateAndAttachDevice and that would lead to deadlock.
	//	auto peripheralProfile = profile.m_Gateway.m_Peripherals.Find(did);
	//	peripheralProfile->m_StartupArguments = peripheral["startupCommand"];
	//}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json FSecure::C3::Core::Profiler::HandleNewBuildMessage(json const& message)
{
	auto newBuildId = message.at("BuildId").get<BuildId::UnderlyingIntegerType>();
	auto const& command = message.at("Command");
	auto commandBinary = TranslateStartupCommand(command);
	auto response = json
	{
		{"BinaryCommand", base64::encode(commandBinary)},
	};
	{
		// Add build to profiler
		auto arch = message.at("Arch").get<std::string>();
		std::transform(arch.begin(), arch.end(), arch.begin(), [](char c) { return std::tolower(c); });
		auto isX64 = arch == "x64";
		Get().m_Gateway.AddAgentBuild(newBuildId, { isX64, false, command });
	}

	return response;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json FSecure::C3::Core::Profiler::Gateway::CreateProfileSnapshot() const
{
	auto gateway = m_Gateway.lock();
	if (!gateway)
		return {};

	// Fill in basic data.
	json profile = {
		{ "agentId", gateway->m_AgentId.ToString() },
		{ "buildId", gateway->m_BuildId.ToString() },
		{"_LastDeviceId", m_LastDeviceId },
		{ "timestamp", m_LastSeen },
		{ "isActive", true}
	};
	if (!m_ErrorState.empty())
		profile["error"] = m_ErrorState;

	// Populate output json with all containers and their elements Profiles.
	profile["channels"] = m_Channels.CreateProfileSnapshot();
	profile["peripherals"] = m_Peripherals.CreateProfileSnapshot();
	profile["routes"] = m_Routes.CreateProfileSnapshot();
	profile["connectors"] = m_Connectors.CreateProfileSnapshot();
	profile["relays"] = m_Agents.CreateProfileSnapshot();

	json registeredBuilds;
	for (auto b : m_AgentBuilds)
	{
		registeredBuilds.push_back
		(
			{
				{"_bid", b.first.ToUnderlyingType()},
				{"_ban", b.second.m_IsBanned},
				{"_x64", b.second.m_IsX64},
				{"_startCmd", b.second.m_StartupCmd},
			}
		);
	}
	profile["_RegisteredBuilds"] = registeredBuilds;

	return profile;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Agent::Agent(std::weak_ptr<Profiler> owner, AgentId agentId, BuildId buildId, FSecure::Crypto::PublicKey encryptionKey, bool isBanned, int32_t lastSeen, bool isX64, HostInfo hostInfo)
	: Relay(owner, agentId, buildId, lastSeen)
	, m_EncryptionKey(encryptionKey)
	, m_HostInfo(std::move(hostInfo))
	, m_IsBanned(isBanned)
	, m_IsX64(isX64)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json FSecure::C3::Core::Profiler::Agent::CreateProfileSnapshot() const
{
	// Fill in basic data.
	json profile = {
		{ "agentId", m_Id.ToString() },
		{ "buildId", m_BuildId.ToString() },
		{ "publicKey", m_EncryptionKey.ToBase64() },
		{ "_LastDeviceId", m_LastDeviceId },
		{ "timestamp", m_LastSeen },
		{ "hostInfo", m_HostInfo },
		{ "isActive", FSecure::Utils::TimeSinceEpoch() - m_LastSeen < 300 }
	};
	if (!m_ErrorState.empty())
		profile["error"] = m_ErrorState;

	// Populate output json with all containers and their elements Profiles.
	profile["channels"] = m_Channels.CreateProfileSnapshot();
	profile["peripherals"] = m_Peripherals.CreateProfileSnapshot();
	profile["routes"] = m_Routes.CreateProfileSnapshot();

	return profile;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Agent::ParseAndRunCommand(json const& jCommandElement) noexcept(false)
{
	auto profiler = m_Owner.lock();
	if (!profiler)
		return; // probably shutting down

	// check if the command should be run on device
	std::optional<DeviceId> deviceId;
	bool deviceIsChannel = false; // have meaning only when it is command for device.
	if (auto jChannelId = jCommandElement.find("channelId"); jChannelId != jCommandElement.end() && !jChannelId->is_null())
	{
		if (auto channel = m_Channels.Find(jChannelId->get<std::string>()); channel)
		{
			deviceId = channel->m_Id;
			deviceIsChannel = true;
		}
		else
			throw std::runtime_error{ "Unknown ChannelId." };
	}
	else if (auto jPeripheralId = jCommandElement.find("peripheralId"); jPeripheralId != jCommandElement.end() && !jPeripheralId->is_null())
	{
		if (auto peripheral = m_Peripherals.Find(jPeripheralId->get<std::string>()); peripheral)
			deviceId = peripheral->m_Id;
		else
			throw std::runtime_error{ "Unknown PeripheralId." };
	}

	auto commandWithArgs = base64::decode<ByteVector>(jCommandElement["Command"]["ByteForm"].get<std::string>());

	auto gateRelay = profiler->m_Gateway->m_Gateway.lock();
	if (!gateRelay)
		return; // probably shutting down

	if (deviceId)
	{
		std::function<void()> finalizer = []() {};

		auto commandReadView = ByteView{ commandWithArgs };
		auto commandId = commandReadView.Read<std::uint16_t>();
		if (commandId > static_cast<std::uint16_t>(-256))
		{
			// generic interface commands
			switch (static_cast<FSecure::C3::Command>(commandId))
			{
			case FSecure::C3::Command::Close:
				finalizer = [&]()
				{
					if (deviceIsChannel)
					{
						m_Channels.TryRemove(*deviceId);
						m_Routes.RemoveIf([deviceId](Profiler::Route const& route) { return route.m_OutgoingDevice == deviceId; });
					}
					else
					{
						// Find connector hash
						auto element = m_Peripherals.Find(*deviceId);
						if (!element)
							return;

						auto connectorHash = profiler->GetBinderTo(element->m_TypeHash);

						// remove peripheral
						m_Peripherals.TryRemove(*deviceId);

						// Get connector
						auto connector = gateRelay->m_Connectors.Find([&](auto const& e) { return e->GetNameHash() == connectorHash; });
						if (!connector)
							return;

						// Remove connection.
						connector->CloseConnection(ByteVector::Create(RouteId{ m_Id, *deviceId }));
					}
				};
				break;
			case FSecure::C3::Command::UpdateJitter:
				finalizer = [this, deviceId, deviceIsChannel, commandReadView]() mutable
				{
					Device* device = deviceIsChannel ? m_Channels.Find(*deviceId) : m_Peripherals.Find(*deviceId);
					if (!device)
						throw std::runtime_error{ "Device not found" };

					device->m_Jitter.first = FSecure::Utils::ToMilliseconds(commandReadView.Read<float>());
					device->m_Jitter.second = FSecure::Utils::ToMilliseconds(commandReadView.Read<float>());
				};
				break;
			default:
				break;
			}
		}

		auto route = gateRelay->FindRoute(m_Id);
		if (!route)
			throw std::runtime_error("Failed to find route to agent id = " + m_Id.ToString());

		auto outgoingChannel = route->m_Channel.lock();
		if (!outgoingChannel)
			throw std::runtime_error("Tried to send command through dead channel"); // TODO maybe try through different route

		auto query = ProceduresG2X::RunCommandOnDeviceQuery::Create(route->m_RouteId, gateRelay->m_Signature, m_EncryptionKey, gateRelay->m_DecryptionKey, *deviceId, ByteView{ commandWithArgs });
		gateRelay->LockAndSendPacket(query->ComposeQueryPacket(), outgoingChannel);
		finalizer();
	}
	else// If we're here then let NodeRelay run Command on itself.
	{
		PerformCreateCommand(jCommandElement);
		RunCommand(commandWithArgs);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Agent::RunCommand(ByteView commandWithArguments)
{
	auto commandReadView = commandWithArguments;
	auto commandId = commandReadView.Read<std::uint16_t>();

	// this function handle only last part  of commands range.
	if (commandId <= static_cast<uint16_t>(-256))
		return;

	auto profiler = m_Owner.lock();
	if (!profiler)
		return; // probably shutting down

	auto gateRelay = profiler->m_Gateway->m_Gateway.lock();
	if (!gateRelay)
		return; // probably shutting down

	auto route = gateRelay->FindRoute(m_Id);
	if (!route)
		throw std::runtime_error("Failed to find route to agent id = " + m_Id.ToString());

	std::function<void()> finalizer = []() {};
	switch (static_cast<Command>(commandId))
	{
	case Command::Close:
	{
		finalizer = [&]()
		{
			auto owner = m_Owner.lock();
			if (!owner)
				throw std::runtime_error{ "Cannot obtain owner" };

			m_Channels.Clear();
			for (auto&& element : m_Peripherals.GetUnderlyingContainer())
			{
				auto connectorHash = profiler->GetBinderTo(element.m_TypeHash);

				auto connector = gateRelay->m_Connectors.Find([&](auto const& e) { return e->GetNameHash() == connectorHash; });
				if (!connector)
					break;

				// Remove connection.
				connector->CloseConnection(ByteVector::Create(RouteId{ m_Id, element.m_Id }));
			}

			m_Peripherals.Clear();
			owner->Get().m_Gateway.m_Agents.Remove(m_Id);
		};
		break;
	}
	case Command::CreateRoute:
	{
		finalizer = [this, commandReadView]() mutable
		{
			auto [ridStr, didStr, isNbr] = commandReadView.Read<std::string_view, std::string_view, bool>();
			ReAddRoute(ridStr, didStr, isNbr);
		};
		break;
	}
	case Command::RemoveRoute:
	{
		finalizer = [this, commandReadView]() mutable
		{
			ReRemoveRoute(commandReadView.Read<std::string_view>());
		};
		break;
	}
	case Command::SetGRC:
	{
		finalizer = [this, commandReadView]() mutable
		{
			auto did = DeviceId{ commandReadView.Read<std::string_view>() };
			if (!m_Channels.Find(did))
				throw std::runtime_error{ "Channel not found" };

			for (auto& e : m_Channels.GetUnderlyingContainer())
				e.m_IsReturnChannel = e.m_Id == did;
		};
		break;
	}
	case Command::Ping:
		break;
	default:
		throw std::runtime_error("Profiler received an unknown command for agent id: " + m_Id.ToString());
	}

	auto outgoingChannel = route->m_Channel.lock();
	if (!outgoingChannel)
		throw std::runtime_error("Tried to send command through dead channel"); // TODO maybe try through different route

	auto query = ProceduresG2X::RunCommandOnAgentQuery::Create(route->m_RouteId, gateRelay->m_Signature, m_EncryptionKey, gateRelay->m_DecryptionKey, commandWithArguments);
	gateRelay->LockAndSendPacket(query->ComposeQueryPacket(), outgoingChannel);
	finalizer();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Agent::PerformCreateCommand(json const& jCommandElement)
{
	auto profiler = m_Owner.lock();
	if (!profiler)
		return; // probably shutting down

	auto gateRelay = profiler->m_Gateway->m_Gateway.lock();
	if (!gateRelay)
		return; // probably shutting down

	auto route = gateRelay->FindRoute(m_Id);
	if (!route)
		throw std::runtime_error("Failed to find route to agent id = " + m_Id.ToString());

	auto commandWithArguments = base64::decode<ByteVector>(jCommandElement["Command"]["ByteForm"].get<std::string>());

	// check if command is a create device command -> then we need to assign deviceId and retreive its hash and repack commandWithArguments
	// [CommandId{CreateAndAttachDevice}(u16)][NewDeviceId(u16)][NewDeviceTypeHash(HashT)][arguments]
	auto commandReadView = ByteView{ commandWithArguments };
	auto commandId = commandReadView.Read<std::uint16_t>();
	auto const& createCommands = profiler->m_Gateway->m_CreateCommands;
	auto command = std::find_if(createCommands.cbegin(), createCommands.cend(), [commandId](Gateway::CreateCommand const& cc) { return cc.m_IsDevice && cc.m_Id == commandId; });

	// this function will only suport create commands
	if (command == createCommands.cend())
		return;

	// it is a create command
	DeviceId newDeviceId = ++m_LastDeviceId;
	ByteVector repacked;
	repacked.Write(Command::AddDevice, newDeviceId, command->m_IsNegotiableChannel, command->m_Hash);
	if (auto binder = profiler->GetBinderTo(command->m_Hash); binder && command->m_IsDevice) // peripheral, check if payload is needed.
	{
		auto connector = profiler->m_Gateway->m_Gateway.lock()->GetConnector(binder);
		if (!connector)
			throw std::runtime_error{ "Connector for requested peripheral is closed" };

		auto updatedArguments = connector->PeripheralCreationCommand(ByteVector::Create(RouteId{ route->m_RouteId.GetAgentId(), newDeviceId }), commandReadView, m_IsX64);
		repacked.Concat(updatedArguments);
	}
	else
	{
		repacked.Concat(commandReadView);
	}

	commandWithArguments = repacked;

	auto outgoingChannel = route->m_Channel.lock();
	if (!outgoingChannel)
		throw std::runtime_error("Tried to send command through dead channel"); // TODO maybe try through different route

	// push json with startup arguments to some container, use it if channel is created.
	AddScheduledDevice(newDeviceId, jCommandElement["Command"]);

	auto query = ProceduresG2X::RunCommandOnAgentQuery::Create(route->m_RouteId, gateRelay->m_Signature, m_EncryptionKey, gateRelay->m_DecryptionKey, commandWithArguments);
	gateRelay->LockAndSendPacket(query->ComposeQueryPacket(), outgoingChannel);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Channel* FSecure::C3::Core::Profiler::Agent::ReAddChannel(Device::Id did, HashT typeNameHash, bool isReturnChannel /*= false*/, bool isNegotiationChannel /*= false*/)
{
	auto channel = Relay::ReAddChannel(did, typeNameHash, isReturnChannel, isNegotiationChannel);

	if (auto it = m_ScheduledDevices.find(did.ToUnderlyingType()); it != m_ScheduledDevices.cend())
		channel->m_StartupArguments = it->second;

	return channel;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Device* FSecure::C3::Core::Profiler::Agent::ReAddPeripheral(Device::Id did, HashT typeNameHash)
{
	auto device = Relay::ReAddPeripheral(did, typeNameHash);

	if (auto it = m_ScheduledDevices.find(did.ToUnderlyingType()); it != m_ScheduledDevices.cend())
		device->m_StartupArguments = it->second;

	return device;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Agent::AddScheduledDevice(DeviceId deviceId, json command)
{
	m_ScheduledDevices.emplace(deviceId.ToUnderlyingType(), std::move(command));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Channel* FSecure::C3::Core::Profiler::Agent::FindGrc()
{
	for (auto& e : m_Channels.GetUnderlyingContainer())
		if (e.m_IsReturnChannel)
			return &e;

	return nullptr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Gateway::Gateway(std::weak_ptr<Profiler> owner, std::string name, std::shared_ptr<GateRelay> gateway)
	: Relay(owner, gateway->m_AgentId, gateway->m_BuildId, FSecure::Utils::TimeSinceEpoch())
	, m_Name(std::move(name))
	, m_Gateway(gateway)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::ParseAndRunCommand(json const& jCommandElement) noexcept(false)
{
	auto commandWithArgs = base64::decode<ByteVector>(jCommandElement["Command"]["ByteForm"].get<std::string>());
	auto commandReadView = ByteView{ commandWithArgs };
	auto conditionalRun = [&](auto jsonEntryToFind, bool isDevice) -> bool
	{
		if (auto jConnectorId = jCommandElement.find(jsonEntryToFind); jConnectorId != jCommandElement.end() && !jConnectorId->is_null())
		{
			auto id = std::stoull(jConnectorId->template get<std::string>(), nullptr, 16); // throws on error.

			if (isDevice)
			{
				auto gateway = m_Gateway.lock();
				if (auto device = gateway->FindDevice(FSecure::Utils::SafeCast<DeviceId::UnderlyingIntegerType>(id)); device)
				{
					auto localView = commandReadView;
					switch (FSecure::C3::Command(localView.Read<std::uint16_t>()))
					{
						case FSecure::C3::Command::UpdateJitter:
						{
							Device* profilerElement = m_Channels.Find(device->GetDid());
							if (!profilerElement)
								profilerElement = m_Peripherals.Find(device->GetDid());

							if (!profilerElement)
								throw std::runtime_error{ "Device not found" };

							profilerElement->m_Jitter.first = FSecure::Utils::ToMilliseconds(localView.Read<float>());
							profilerElement->m_Jitter.second = FSecure::Utils::ToMilliseconds(localView.Read<float>());
							break;
						}
						case FSecure::C3::Command::Close:
						{
							if (auto profilerElement = m_Peripherals.Find(device->GetDid()))
							{
								auto connectorHash = m_Owner.lock()->GetBinderTo(profilerElement->m_TypeHash);
								auto connector = m_Gateway.lock()->m_Connectors.Find([&](auto const& e) { return e->GetNameHash() == connectorHash; });
								if (!connector)
									break;

								// Remove connection.
								connector->CloseConnection(ByteVector::Create(RouteId{ m_Id, device->GetDid() }));
							}
							else if (auto profilerElemnt = m_Channels.Find(device->GetDid()))
							{
								m_Routes.RemoveIf([did = device->GetDid()](Profiler::Route const& route) { return route.m_OutgoingDevice == did; });
							}
							break;
						}
						default:
							break;
					}

					device->RunCommand(commandReadView);
					return true;
				}

			}
			else
			{
				if (auto connector = m_Connectors.Find(FSecure::Utils::SafeCast<HashT>(id)); connector)
					return connector->RunCommand(commandReadView), true;
			}

			throw std::runtime_error{ "Unknown Id." };
		}

		return false;
	};

	if (conditionalRun("connectorId", false))	return;
	if (conditionalRun("channelId", true))	return;
	if (conditionalRun("peripheralId", true))	return;

	// If we're here then let NodeRelay run Command on itself.
	RunCommand(commandReadView);

	// try performing create command.
	PerformCreateCommand(jCommandElement);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json FSecure::C3::Core::Profiler::Gateway::GetCapability()
{
	// Request access to Gateway object.
	auto gateway = m_Gateway.lock();
	if (!gateway)
		return {};

	// TODO This function require refactoring.

	// Construct the InitialPacket.
	json initialPacket = json::parse(gateway->m_InterfaceFactory.GetCapability());

	for (auto& interface : initialPacket["channels"])
		EnsureCreateExists(interface);

	// Create method in interface is constructor. It must be a relay/gateway command.
	// initialPacket is copied to original to prevent iterator invalidation.
	// last 256 commands will be reserved for common commands.
	auto modifyEntry = [&, id = static_cast<uint16_t>(-257), oryginal = initialPacket](std::vector<std::string> const& relayTypes, auto interfaceType, std::vector<std::string> prefix, bool isDevice) mutable
	{
		auto idToErase = 0;
		std::vector<std::unordered_map<std::string, std::vector<json>>> buffer;
		buffer.resize(prefix.size());
		for (auto&& element : oryginal[interfaceType])
		{
			try
			{
				for (auto i = 0u; i < prefix.size(); ++i)
				{
					auto arguments = element.at("create").at("arguments");
					if (i) // NegotiationChannel command
					{
						if (arguments.empty() || arguments[0].size() != 2)
							continue;

						arguments[0] = { {"type", "string"}, {"name", "Negotiation Identifier"}, {"randomize", true}, {"description", "One identifier used to negotiate identifiers for each joining relay"} };
					}

					for (auto&& relayType : relayTypes)
						buffer[i][relayType].push_back(json{ {"name", prefix[i] + element["name"].template get<std::string>()}, {"arguments", arguments}, {"id", id} });

					m_CreateCommands.push_back({ id, initialPacket[interfaceType][idToErase]["type"].template get<uint32_t>(), isDevice, !!i }); // store command id and hash.
					--id;
				}

				// modify initial Packet with extra entries.
				initialPacket[interfaceType][idToErase].erase("create");
				AddBuildInCommands(initialPacket[interfaceType][idToErase], isDevice);
			}
			catch (std::exception& e)
			{
				m_Gateway.lock()->Log({ std::string("Exception caught when parsing interface capability. ") + e.what(), LogMessage::Severity::Error });
			}

			++idToErase;
		}

		// move commands from buffer to modified json in correct order.
		for (auto prefixEntryIterator = buffer.rbegin(); prefixEntryIterator != buffer.rend(); ++prefixEntryIterator)
			for (auto&& relayEntry : *prefixEntryIterator)
				for (auto &&e : relayEntry.second)
				initialPacket[relayEntry.first]["commands"].push_back(std::move(e));
	};

	m_CreateCommands.clear(); // clear old create commands.
	modifyEntry({ "gateway", "relay"}, "channels", { "AddChannel", "AddNegotiationChannel" }, true);
	modifyEntry({ "gateway", "relay" }, "peripherals", { "AddPeripheral" }, true);
	modifyEntry({ "gateway" }, "connectors", { "TurnOnConnector" }, false);


	// Add common commands for relay.
	auto addRelayCommand = [&](std::vector<std::string> relayTypes, json const& newCommand)
	{
		for (auto&& relayType : relayTypes)
			initialPacket[relayType]["commands"].push_back(newCommand);
	};
	addRelayCommand({ "gateway", "relay" }, json{ {"name", "Close"}, {"id", static_cast<std::underlying_type_t<Command>>(Command::Close) }, {"arguments", json::array()} });

	addRelayCommand({ "gateway", "relay" }, json{ {"name", "CreateRoute"}, {"id", static_cast<std::underlying_type_t<Command>>(Command::CreateRoute) }, {"arguments", {
						{{"type", "string"}, {"name", "RouteID"}, {"description", "Id of route in string form."}, {"min", 1}},
						{{"type", "string"}, {"name", "DeviceId"}, {"description", "Id of device in string form."}, {"min", 1}},
						{{"type", "boolean"}, {"name", "Neighbor"}, {"description", "Informs if relay is direct neighbor."}, {"defaultValue", true}}
					}} });

	addRelayCommand({ "gateway", "relay" }, json{ {"name", "RemoveRoute"}, {"id", static_cast<std::underlying_type_t<Command>>(Command::RemoveRoute) }, {"arguments", {
					{{"type", "string"}, {"name", "RouteID"}, {"description", "Id of route in string form."}, {"min", 1}}
				}} });

	addRelayCommand({ "relay" }, json{ {"name", "SetGatewayReturnChannel"}, {"id", static_cast<std::underlying_type_t<Command>>(Command::SetGRC) }, {"arguments", {
				{{"type", "string"}, {"name", "DeviceID"}, {"description", "Id of device in string form."}, {"min", 1}}
			}} });

	addRelayCommand({ "relay" }, json{ {"name", "Ping"}, {"id", static_cast<std::underlying_type_t<Command>>(Command::Ping) }, {"arguments", json::array() } });

	addRelayCommand({ "gateway" }, json{ {"name", "ClearNetwork"}, {"id", static_cast<std::underlying_type_t<Command>>(Command::ClearNetwork) }, {"arguments", {
					{{"type", "boolean"}, {"name", "Are you sure?"}, {"description", "Confirm clearing the network. All network state will be lost, this can not be undone."}, {"default", false}}
				}} });


	// add extra fields.
	auto gatewayPushBack = [&](auto key, auto value)
	{
		initialPacket["gateway"][key] = value;
	};

	gatewayPushBack("agentId", m_Id.ToString());
	gatewayPushBack("buildId", m_BuildId.ToString());
	gatewayPushBack("publicKey", Crypto::ExtractPublic(gateway->m_Signature).ToBase64());
	gatewayPushBack("broadcastKey", gateway->m_BroadcastKey.ToBase64());
	gatewayPushBack("name", m_Name);

	return initialPacket;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::EnsureCreateExists(json& interface)
{
	if (!interface.contains("create"))
		interface["create"] = json::parse(R"(
{
	"arguments" :
		[
			{
				"type": "binary",
				"description": "Blob of data that will be provided to Channel constructor.",
				"name": "arguments"
			}
		]
}
)");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::AddBuildInCommands(json& interface, bool isDevice)
{
	interface["commands"].push_back(json{ {"name", isDevice ? "Close" : "TurnOff"}, {"id", static_cast<std::underlying_type_t<Command>>(Command::Close) }, {"arguments", json::array()} });

	if (isDevice)
		interface["commands"].push_back(json{ {"name", "Set UpdateDelayJitter"}, {"description", "Set delay between receiving function calls."}, {"id", static_cast<std::underlying_type_t<Command>>(Command::UpdateJitter) },
			{"arguments", {
				{{"type", "float"}, {"name", "Min"}, {"description", "Minimal delay in seconds"}, {"min", 0.03}},
				{{"type", "float"}, {"name", "Max"}, {"description", "Maximal delay in seconds. "}, {"min", 0.03}}
			}} });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::RunCommand(ByteView commandWithArguments)
{
	auto pin = m_Gateway.lock();
	if (!pin)
		return;

	switch (static_cast<Command>(commandWithArguments.Read<std::underlying_type_t<Command>>()))
	{
	case Command::Close:
		pin->Close();
		break;
	case Command::CreateRoute:
	{
		pin->CreateRoute(commandWithArguments);
		auto [ridStr, didStr, isNbr] = commandWithArguments.Read<std::string_view, std::string_view, bool>();
		ReAddRoute(ridStr, didStr, isNbr);
		break;
	}
	case Command::RemoveRoute:
	{
		pin->RemoveRoute(commandWithArguments);
		ReRemoveRoute(commandWithArguments.Read<std::string_view>());
		break;
	}
	case Command::ClearNetwork:
	{
		// Clear real gateway
		pin->Reset();

		// clear profiler view
		{
			auto profiler = m_Owner.lock();
			auto profile = profiler->Get();
			profile.m_Gateway.Reset();
		}
		break;
	}
	default:
		break;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::PerformCreateCommand(json const& jCommandElement)//GateRelay& gate, std::uint16_t commandId, ByteView arguments)
{
	auto pin = m_Gateway.lock();
	if (!pin)
		throw std::runtime_error{ "Cannot lock gateway" };

	auto& gate = *pin;
	auto command = base64::decode<ByteVector>(jCommandElement["Command"]["ByteForm"].get<std::string>());
	auto arguments = ByteView{ command };
	auto commandId = arguments.Read<uint16_t>();
	auto profiler = m_Owner.lock(); // bad code, refactor.

	auto createCommandIt = std::find_if(m_CreateCommands.cbegin(), m_CreateCommands.cend(), [commandId](auto const& cc) {return cc.m_Id == commandId;  });
	if (createCommandIt == m_CreateCommands.cend())
		return;

	auto createCommand = *createCommandIt;

	if (createCommand.m_IsDevice)
	{
		ByteVector updatedArguments;
		//createCommand.

		auto binder = profiler->GetBinderTo(createCommand.m_Hash);
		if (binder)
		{
			auto connector = gate.GetConnector(binder);
			if (!connector)
				throw std::runtime_error{ "Connector for requested peripheral is closed" };

			updatedArguments = connector->PeripheralCreationCommand(ByteVector::Create(RouteId{ gate.GetAgentId(), DeviceId(m_LastDeviceId + 1) }), arguments, FSecure::Utils::IsProcess64bit());
			arguments = updatedArguments;
		}

		auto device = gate.CreateAndAttachDevice(++m_LastDeviceId, createCommand.m_Hash, createCommand.m_IsNegotiableChannel, arguments);

		// TODO refactor - seriously bad code CreateAndAttach calls ReAddChannel / ReAddDevice and here we search for it
		Device* deviceView;
		if (device->IsChannel())
			deviceView = profiler->Get().m_Gateway.m_Channels.Find(device->GetDid());
		else
			deviceView = profiler->Get().m_Gateway.m_Peripherals.Find(device->GetDid());

		if (deviceView)
			deviceView->m_StartupArguments = jCommandElement["Command"];
	}
	else
	{
		gate.TurnOnConnector(createCommand.m_Hash, arguments);
		auto connectorView = profiler->Get().m_Gateway.m_Connectors.Find(createCommand.m_Hash);
		if (connectorView)
			connectorView->m_StartupArguments = jCommandElement["Command"];
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::ReTurnOnConnector(HashT typeNameHash, std::shared_ptr<ConnectorBridge> connector)
{
	m_Connectors.Add(typeNameHash, Connector{ m_Owner, typeNameHash, connector });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::ReTurnOffConnector(HashT connectorNameHash)
{
	m_Connectors.Remove(connectorNameHash);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::ReDeleteChannel(DeviceId iidOfDeviceToDetach)
{
	m_Channels.Remove(iidOfDeviceToDetach);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::ReDeletePeripheral(DeviceId iidOfDeviceToDetach)
{
	m_Peripherals.Remove(iidOfDeviceToDetach);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Agent* FSecure::C3::Core::Profiler::Gateway::ReAddAgent(AgentId agentId, BuildId buildId, FSecure::Crypto::PublicKey encryptionKey, bool isBanned, int32_t lastSeen, HostInfo hostInfo)
{
	auto build = m_AgentBuilds.find(buildId);
	if (build == m_AgentBuilds.cend())
		throw std::runtime_error{ "Tried to add agent with unknown buildId" };
	if (build->second.m_IsBanned)
		return nullptr;
	auto agent = m_Agents.Add(agentId, Agent{ m_Owner, agentId, buildId, encryptionKey, isBanned, lastSeen, build->second.m_IsX64, std::move(hostInfo) });
	agent->AddScheduledDevice(0u, build->second.m_StartupCmd);
	return agent;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Agent* FSecure::C3::Core::Profiler::Gateway::ReAddRemoteAgent(RouteId childRouteId, BuildId buildId, FSecure::Crypto::PublicKey encryptionKey, RouteId ridOfConectionPlace, HashT childGrcHash, int32_t lastSeen, HostInfo hostInfo)
{
	// add agent
	auto newAgent = ReAddAgent(childRouteId.GetAgentId(), buildId, encryptionKey, false, lastSeen, std::move(hostInfo)); // TODO check if is banned

	// add routes
	Relay* current = this;
	while (current->m_Id != ridOfConectionPlace.GetAgentId())
	{
		DeviceId outDevice = current->FindDirectionDevice(ridOfConectionPlace.GetAgentId());
		current->ReAddRoute(childRouteId, outDevice, false);
		current = FindNeighborOnDevice(*current, outDevice);
	}

	// add route to neighboring device
	current->ReAddRoute(childRouteId, ridOfConectionPlace.GetInterfaceId(), true);

	// add return channel to new agent
	newAgent->ReAddChannel(childRouteId.GetInterfaceId(), childGrcHash, true);
	return newAgent;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Relay::UpdateFromNegotiationChannel(DeviceId negotiationDid, DeviceId newDeviceId, std::string newInputId, std::string newOutputId)
{
	auto oldDeviceProfile = m_Channels.Find(negotiationDid);
	auto newDeviceProfile = m_Channels.Find(newDeviceId);

	if (oldDeviceProfile && newDeviceProfile)
	{
		newDeviceProfile->m_StartupArguments = oldDeviceProfile->m_StartupArguments;
		newDeviceProfile->m_StartupArguments["arguments"][0] = { { {"name", "Input ID"}, {"type", "string"}, {"value", newInputId} }, { {"name", "Output ID"}, {"type", "string"}, {"value", newOutputId} } };
		auto oldDeviceCmd = base64::decode<ByteVector>(oldDeviceProfile->m_StartupArguments["ByteForm"].get<std::string>());
		auto oldDeviceCmdReadView = ByteView{ oldDeviceCmd };
		auto [cmdId, uniqueId] = oldDeviceCmdReadView.Read<uint16_t, std::string>();
		auto newDeviceCmd = ByteVector{}.Write(cmdId, newInputId, newOutputId).Concat(oldDeviceCmdReadView);
		newDeviceProfile->m_StartupArguments["ByteForm"] = base64::encode(newDeviceCmd);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Agent* FSecure::C3::Core::Profiler::Gateway::FindNeighborOnDevice(Relay& relay, DeviceId did)
{
	auto& routes = relay.m_Routes.GetUnderlyingContainer();
	auto it = std::find_if(routes.begin(), routes.end(), [&](auto& e) { return e.m_IsNeighbour && e.m_OutgoingDevice == did; });
	if (it == routes.end())
		throw std::logic_error{ "There is no route from provided agent" };

	auto ret = m_Agents.Find(it->m_Id.GetAgentId());
	if (!ret)
		throw std::logic_error{ "There is no route from provided agent" };

	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::UpdateRouteTimestamps(AgentId agentId, int32_t timestamp)
{
	Agent* agent = m_Agents.Find(agentId);
	if (!agent)
		throw std::runtime_error{ "Agent not found" };

	for (auto e : GetPathFromAgent(agent))
		e->m_LastSeen = timestamp;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Agent* FSecure::C3::Core::Profiler::Gateway::FindGatewaySideAgent(Agent* agent)
{
	auto& channels = agent->m_Channels.GetUnderlyingContainer();
	auto grcIt = std::find_if(channels.begin(), channels.end(), [](auto& e) {return e.m_IsReturnChannel; });
	if (grcIt == channels.end())
		throw std::runtime_error{ "GRC not found" };

	for (auto& current : m_Agents.GetUnderlyingContainer())
	{
		for (auto& route : current.m_Routes.GetUnderlyingContainer())
		{
			if (route.m_IsNeighbour && route.m_Id.GetAgentId() == agent->m_Id && route.m_Id.GetInterfaceId() == grcIt->m_Id)
				return &current;
		}
	}

	return nullptr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::C3::Core::Profiler::Agent*> FSecure::C3::Core::Profiler::Gateway::GetPathFromAgent(Agent* agent)
{
	std::vector<Agent*> ret;
	auto depthLimit = 128;
	while (agent && agent->m_Id != m_Id)
	{
		if (!(--depthLimit))
			return {};

		ret.push_back(agent);
		agent = FindGatewaySideAgent(agent);
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool FSecure::C3::Core::Profiler::Gateway::ConnectionExist(AgentId agentId)
{
	if (auto path = GetPathFromAgent(m_Agents.Find(agentId)); !path.empty())
		for (auto& e : m_Routes.GetUnderlyingContainer())
			if (e.m_IsNeighbour && e.m_Id.GetAgentId() == path.back()->m_Id)
				return true;

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::AddAgentBuild(BuildId bid, BuildProperties properties)
{
	auto emplaced = m_AgentBuilds.emplace(bid, properties);
	if (!emplaced.second)
		throw std::logic_error{ "Tried to add new build with existing buildId" };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::ConditionalUpdateChannelParameters(RouteId connectionPlace)
{
	try
	{
		// parent is known
		Relay* parent = connectionPlace.GetAgentId() == m_Id ? static_cast<Relay*>(this) : m_Agents.Find(connectionPlace.GetAgentId());
		if (!parent)
			return;

		auto parentChannel = parent->m_Channels.Find(connectionPlace.GetInterfaceId());
		if (!parentChannel || parentChannel->m_StartupArguments.is_null())
			return;

		Agent* agent = FindNeighborOnDevice(*parent, connectionPlace.GetInterfaceId());
		auto agentChannel = agent->FindGrc();
		if (!agentChannel)
			return;

		// Channel does not have startup arguments.
		if (!agentChannel->m_StartupArguments.is_null())
			return;

		// build started with neg channel
		auto buildIterator = m_AgentBuilds.find(agent->m_BuildId);
		if (buildIterator == m_AgentBuilds.end() || buildIterator->second.m_StartupCmd["command"].get<std::string>().find("AddNegotiationChannel") == std::string::npos)
			return;


		// update
		json startupArguments = { {"arguments", json::array()} };
		startupArguments["arguments"][0][0] = parentChannel->m_StartupArguments["arguments"][0][1];
		startupArguments["arguments"][0][1] = parentChannel->m_StartupArguments["arguments"][0][0];
		for (auto i = 1u; i < buildIterator->second.m_StartupCmd["arguments"].size(); ++i)
			startupArguments["arguments"][i] = buildIterator->second.m_StartupCmd["arguments"][i];

		agentChannel->m_StartupArguments = startupArguments;
	}
	catch (const std::exception&)
	{
		return;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::Reset()
{
	m_Agents.Clear();
	m_Connectors.Clear();
	m_Peripherals.Clear();
	m_Channels.Clear();
	m_Routes.Clear();
	m_AgentBuilds.clear();
	m_LastDeviceId = 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Device::RunCommand(ByteView commandWithArguments)
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Device::Device(std::weak_ptr<Profiler> owner, Id id, HashT typeHash)
	: ProfileElement(owner)
	, m_Id(id)
	, m_TypeHash(typeHash)
{
	if (auto ptrCh = InterfaceFactory::Instance().GetInterfaceData<AbstractChannel>(m_TypeHash); ptrCh)
		m_Jitter = ptrCh->m_StartupJitter;
	else if (auto ptrP = InterfaceFactory::Instance().GetInterfaceData<AbstractPeripheral>(m_TypeHash); ptrP)
		m_Jitter = ptrP->m_StartupJitter;
	else
		throw std::runtime_error("Type hash does is not device: " + std::to_string(m_TypeHash));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Route::Route(std::weak_ptr<Profiler> owner, RouteId id, Device::Id outgoingDeviceId, bool isNeighbour)
	: ProfileElement(owner)
	, m_OutgoingDevice(outgoingDeviceId)
	, m_Id(id)
	, m_IsNeighbour(isNeighbour)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json FSecure::C3::Core::Profiler::Route::CreateProfileSnapshot() const
{
	// Construct profile.
	json profile = {
		{ "outgoingInterface", m_OutgoingDevice.ToString() },
		{ "destinationAgent", m_Id.GetAgentId().ToString() },
		{ "receivingInterface", m_Id.GetInterfaceId().ToString() },
		{ "isNeighbour",  m_IsNeighbour},
	};

	// Add state indicators if needed.
	if (!m_ErrorState.empty())
		profile["error"] = m_ErrorState;

	// Return profile.
	return profile;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Route::RunCommand(ByteView commandWithArguments)
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Relay::Relay(std::weak_ptr<Profiler> owner, AgentId agentId, BuildId buildId, int32_t lastSeen)
	: ProfileElement(owner)
	, m_Id(agentId)
	, m_BuildId(buildId)
	, m_LastSeen(lastSeen)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Relay::ParseAndRunCommand(json const& jCommandElement) noexcept(false)
{
	throw std::runtime_error("Relay::ParseAndRunCommand should be overriden");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Relay::RunCommand(ByteView commandWithArguments)
{
	throw std::runtime_error("Relay::RunCommand should be overriden");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Channel* FSecure::C3::Core::Profiler::Relay::ReAddChannel(Device::Id did, HashT typeNameHash, bool isReturnChannel /*= false*/, bool isNegotiationChannel /*= false*/)
{
	auto ret = m_Channels.Add(did, Channel{ m_Owner, did, typeNameHash, isReturnChannel, isNegotiationChannel });
	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Device* FSecure::C3::Core::Profiler::Relay::ReAddPeripheral(Device::Id did, HashT typeNameHash)
{
	auto ret = m_Peripherals.Add(did, Device{ m_Owner, did, typeNameHash });
	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Relay::ReAddRoute(RouteId receivingRid, DeviceId outgoingInterface, bool isNeighbour)
{
	m_Routes.Add(receivingRid, Route{ m_Owner, receivingRid, outgoingInterface, isNeighbour });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Relay::ReRemoveRoute(RouteId rid)
{
	m_Routes.Remove(rid);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::DeviceId FSecure::C3::Core::Profiler::Relay::FindDirectionDevice(AgentId aid)
{
	auto& routes = m_Routes.GetUnderlyingContainer();
	auto it = std::find_if(routes.begin(), routes.end(), [&](auto& e) {return e.m_Id.GetAgentId() == aid; });
	if (it == routes.end())
		throw std::logic_error{ "There is no route to provided agent" };

	return it->m_OutgoingDevice;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Core::Profiler::Gateway::Connector::RunCommand(ByteView commandWithArguments)
{
	if (auto pin = m_Connector.lock(); pin)
		pin->RunCommand(commandWithArguments);
	else
		throw std::runtime_error{ "Connector cannot be obtained" };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Gateway::Connector::Connector(std::weak_ptr<Profiler> owner, Id id, std::shared_ptr<ConnectorBridge> connector)
	: ProfileElement(owner)
	, m_Id(id)
	, m_Connector(connector)
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Profile::Profile(Gateway& gateway)
	: m_Gateway(gateway)
	, m_Lock(m_Mutex)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json FSecure::C3::Core::Profiler::ProfileElement::CreateProfileSnapshot() const
{
	// Start with empty JSON.
	json profile;

	if (!m_ErrorState.empty())
		profile["error"] = m_ErrorState;

	// Done.
	return profile;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::ProfileElement::ProfileElement(std::weak_ptr<Profiler> owner) : m_Owner(owner)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json FSecure::C3::Core::Profiler::Gateway::Connector::CreateProfileSnapshot() const
{
	auto profile = __super::CreateProfileSnapshot();
	profile["iId"] = Identifier(m_Id).ToString();
	profile["type"] = m_Id;
	profile["startupCommand"] = m_StartupArguments;
	if (auto lock = m_Connector.lock(); lock && !lock->GetErrorStatus().empty())
		profile["error"] = lock->GetErrorStatus();

	return profile;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json FSecure::C3::Core::Profiler::Device::CreateProfileSnapshot() const
{
	auto profile = __super::CreateProfileSnapshot();
	profile["iId"] = m_Id.ToString();
	profile["type"] = m_TypeHash;
	profile["startupCommand"] = m_StartupArguments;
	profile["jitter"] = { FSecure::Utils::DoubleSeconds(m_Jitter.first).count(), FSecure::Utils::DoubleSeconds(m_Jitter.second).count() };

	// get error here.
	return profile;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::Channel::Channel(std::weak_ptr<Profiler> owner, Id id, HashT typeHash, bool isReturnChannel /*= false*/, bool isNegotiationChannel /*= false*/)
	: Device(owner, id, typeHash)
	, m_IsReturnChannel(isReturnChannel)
	, m_IsNegotiationChannel(isNegotiationChannel)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json FSecure::C3::Core::Profiler::Channel::CreateProfileSnapshot() const
{
	auto profile = __super::CreateProfileSnapshot();
	profile["isReturnChannel"] = m_IsReturnChannel;
	profile["isNegotiationChannel"] = m_IsNegotiationChannel;

	return profile;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Core::Profiler::SnapshotProxy::SnapshotProxy(Profiler& profiler) :
	m_Profiler(profiler)
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool FSecure::C3::Core::Profiler::SnapshotProxy::CheckUpdates()
{
	m_CurrentSnapshot = m_Profiler.Get().m_Gateway.CreateProfileSnapshot();
	auto currentHash = std::hash<json>{}(m_CurrentSnapshot);
	if (m_PreviousHash && currentHash == *m_PreviousHash)
		return false;

	m_PreviousHash = currentHash;
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
json const& FSecure::C3::Core::Profiler::SnapshotProxy::GetSnapshot() const
{
	return m_CurrentSnapshot;
}

