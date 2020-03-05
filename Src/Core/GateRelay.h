#pragma once

#include "Relay.h"
#include "Common/FSecure/C3/Internals/BackendCommons.h"
#include "Common/FSecure/Sockets/Sockets.hpp"
#include "Common/json/json.hpp"

namespace FSecure::C3::Core
{
	// Forward declarations.
	struct Profiler;
	struct ConnectorBridge;

	/// Relay class specialization that implements a "server" Relay.
	struct GateRelay : Relay, ProceduresG2X::RequestHandler
	{
		// Friendships.
		friend struct Profiler;

		/// Factory method.
		/// @param callbackOnLog callback fired whenever a new Log entry is being added.
		/// @param interfaceFactory reference to interface factory.
		/// @param apiBridgeIp IP address to set up API bridge on.
		/// @param apiBridgePort port to set up API bridge on.
		/// @param signatures a pair of signature keys used to authenticate as Network's Gateway and decrypt authenticated messages from Nodes.
		/// @param broadcastKey Network's symmetric key.
		/// @param buildId Build identifier.
		/// @param snapshotPath path to json file with current state of network. Used in case of gateway restart.
		/// @param agentId Agent identifier.
		/// @param name optional name provided for gateway.
		static std::shared_ptr<GateRelay> CreateAndRun(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory, std::string_view apiBridgeIp,
			std::uint16_t apiBrigdePort, FSecure::Crypto::SignatureKeys const& signatures, FSecure::Crypto::SymmetricKey const& broadcastKey, FSecure::C3::BuildId buildId, std::filesystem::path snapshotPath,
			FSecure::C3::AgentId agentId = FSecure::C3::AgentId::GenerateRandom(), std::string name = "");

		/// Turns on specified Connector.
		/// @param connectorNameHash hash value of Connector's name.
		/// @param commandLine buffer containing Connector's construction parameters.
		/// @throws std::runtime_error if couldn't find factory for specified Connector name hash or if factory was unable to process provided command-line. Throws std::invalid_argument if specified Connector is already turned on.
		virtual void TurnOnConnector(HashT connectorNameHash, ByteView commandLine);

		/// Turns off specified Connector.
		/// @param connectorNameHash hash value of Connector's name.
		/// @throw std::invalid_argument on an attempt of turning off a non-existent Connector.
		virtual void TurnOffConnector(HashT connectorNameHash);

		/// Gets Connector if it's turned on.
		/// @param connectorNameHash hash value of Connector's name.
		/// @return Connector pointer if found or null.
		std::shared_ptr<FSecure::C3::Core::ConnectorBridge> GetConnector(HashT connectorNameHash);

		/// Called whenever an attached Binder Connector wants to send a Command to its Peripheral Binder.
		/// @param command full Command with arguments.
		/// @param routeId address to peripheral.
		virtual void PostCommandToPeripheral(ByteView command, RouteId routeId);

	protected:
		/// Protected ctor.
		/// @param callbackOnLog callback fired whenever a new Log entry is being added.
		/// @param interfaceFactory reference to interface factory.
		/// @param abiBridgeIp IP address to set up API bridge on.
		/// @param apiBridgePort port to set up API bridge on.
		/// @param signatures a pair of signature keys used to authenticate as Network's Gateway and decrypt authenticated messages from Nodes.
		/// @param broadcastKey Network's symmetric key.
		/// @param buildId Build identifier.
		/// @param snapshotPath path to json file with current state of network. Used in case of gateway restart.
		/// @param agentId Agent identifier.
		GateRelay(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory, std::string_view abiBridgeIp, std::uint16_t apiBrigdePort,
			FSecure::Crypto::SignatureKeys const& signatures, FSecure::Crypto::SymmetricKey const& broadcastKey, FSecure::C3::BuildId buildId, std::filesystem::path snapshotPath, FSecure::C3::AgentId agentId = FSecure::C3::AgentId::GenerateRandom());

		/// Close Gateway.
		void Close() override;

		/// Add a new Device.
		/// @param iid preferred Identifier.
		/// @param DeviceNameHash hash value of Device's name.
		/// @param isNegotiationChannel true if channel will support negotiation procedure.
		/// @param commandLine buffer containing Device's construction parameters.
		/// @param negotiationClient true if channel will support negotiation procedure, and should start it.
		/// @return newly created Device.
		/// @throws std::runtime_error if couldn't find factory for specified Device name hash or other exceptions if factory was unable to process provided command-line.
		std::shared_ptr<DeviceBridge> CreateAndAttachDevice(DeviceId iid, HashT deviceNameHash, bool isNegotiationChannel, ByteView commandLine, bool negotiationClient = false) override;

		/// Checks whether particular Agent is banned.
		/// @param agentId ID of the Agent to check.
		bool IsAgentBanned(AgentId agentId) override;

		/// Fired when a S2G protocol packet arrives.
		/// @param packet0 a buffer that contains whole packet.
		/// @param sender a Channel that provided the packet.
		void OnProtocolS2G(ByteView packet0, std::shared_ptr<DeviceBridge> sender) override;

		/// Fired when a G2A protocol packet arrives.
		/// @param packet0 a buffer that contains whole packet.
		/// @param sender a Channel that provided the packet.
		void OnProtocolG2A(ByteView packet0, std::shared_ptr<DeviceBridge> sender) override;

		/// Fired when a G2R protocol packet arrives.
		/// @param packet0 a buffer that contains whole packet.
		/// @param sender a Channel that provided the packet.
		void OnProtocolG2R(ByteView packet0, std::shared_ptr<DeviceBridge> sender) override;

		/// Called whenever an attached Binder Peripheral wants to send a Command to its Connector Binder.
		/// @param command full Command with arguments.
		/// @param senderPeripheral Interface that is sending the Command.
		void PostCommandToConnector(ByteView command, std::shared_ptr<DeviceBridge> senderPeripheral) override;

		/// Handler fired when a N2N::InitializeRoute Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresN2N::InitializeRouteQuery&& query) override;

		/// Handler fired when a S2G::InitializeRoute Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresS2G::InitializeRouteQuery&& query) override;

		/// Handler fired when a N2N::ChannelIdExchangeStep1 Procedure Query arrives.
		/// Gateway opens a new channel and sends parameters to relay.
		/// @param query object representing the Query.
		void On(ProceduresN2N::ChannelIdExchangeStep1) override;

		/// Handler fired when a N2N::ChannelIdExchangeStep Procedure Query arrives.
		/// @param query object representing the Query.
		/// @emarks Gateway should never receive the second step message of channel Id negotiation.
		void On(ProceduresN2N::ChannelIdExchangeStep2) override;

		/// Handler fired when a S2G::AddDeviceResponse Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresS2G::AddDeviceResponse response) override;

		/// Handler fired when a S2G::DeliverToBinder Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresS2G::DeliverToBinder query) override;

		/// Handler fired when a S2G::NewNegotiatedChannelNotification Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresS2G::NewNegotiatedChannelNotification query) override;

		/// Handler fired when a S2G::Notification Procedure Query arrives.
		/// @param query object representing the Query.
		/// @remarks Current implementation supports only timestamp. Notification can be extended to send variety of data about relay state.
		void On(ProceduresS2G::Notification query) override;

		/// Detaches an Device. This operation leads to (delayed) destruction of the Device.
		/// @param iidOfDeviceToDetach ID of the Device to detach.
		/// @throw std::invalid_argument on an attempt of removal of a non-existent Device.
		void DetachDevice(DeviceId const& iidOfDeviceToDetach) override;

		/// Operation removing every interface (Connectors and Devices) from GateRelay.
		/// Interfaces are not guaranteed to be closed after this function returns.
		/// Threads associated with interfaces are scheduled to end, but must end current tasks.
		void CloseDevicesAndConnectors();

		/// Removes routes and closes interfaces @see CloseDevicesAndConnectors().
		void Reset();

	private:
		/// Run API bridge
		/// @param apiBridgeIp IP address to set up API bridge on.
		/// @param apiBridgePort port to set up API bridge on.
		void RunApiBrige(std::string_view apiBrigdeIp, std::uint16_t apiBrigdePort) noexcept;

		/// Called when new message from Controller is received.
		/// Unpacks and schedules actions from message.
		nlohmann::json HandleMessage(nlohmann::json const& message);

		SafeSmartPointerContainer<std::shared_ptr<ConnectorBridge>> m_Connectors;										///< Container for Connectors that are currently turned on.

		Crypto::PublicKey m_AuthenticationKey;																			///< Gateway's pubic key. Used to decrypt authenticated messages.
		Crypto::PrivateSignature m_Signature;																			///< Used to authenticate as Network's Gateway.
		Crypto::SessionKeys m_SessionKeys;																				///< Used for communication with controller.
		FSecure::InitializeSockets m_InitializeSockets;																		///< Sockets initializer object used by API bridge.
		bool m_IsAlive = true;																							///< Equals false if Controller sent the exit Command.

		std::shared_ptr<Profiler> m_Profiler;																			///< Virtual shape of the network.
	};
}
