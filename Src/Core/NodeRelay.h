#pragma once

#include "Relay.h"

namespace FSecure::C3::Core
{
	/// Relay class specialization that implements a "client" Relay.
	struct NodeRelay : Relay, ProceduresG2X::RequestHandler
	{
		/// Factory method.
		/// @param callbackOnLog callback fired whenever a new Log entry is being added.
		/// @param interfaceFactory reference to interface factory.
		/// @param gatewaySignature public signature used by Network's Gateway to authenticate itself.
		/// @param broadcastKey Network's symmetric key.
		/// @param gatewayInitialPackets initial Procedures for this NodeRelay. Should contain creation of a at least a single Channel.
		/// @param buildId Build identifier.
		/// @param agentId Agent identifier.
		/// @param asymmetricKeys asymmetric keys used to communicate with the Gateway.
		static std::shared_ptr<NodeRelay> CreateAndRun(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory, Crypto::PublicSignature const& gatewaySignature,
			Crypto::SymmetricKey const& broadcastKey, std::vector<ByteVector> const& gatewayInitialPackets, BuildId buildId, AgentId agentId = AgentId::GenerateRandom(),
			Crypto::AsymmetricKeys const& asymmetricKeys = Crypto::GenerateAsymmetricKeys());

	protected:
		/// A protected constructor. @see Relay::Relay.
		/// @param callbackOnLog callback fired whenever a new Log entry is being added.
		/// @param interfaceFactory reference to interface factory.
		/// @param gatewaySignature public signature used by Network's Gateway to authenticate itself.
		/// @param broadcastKey Network's symmetric key.
		/// @param buildId Build identifier.
		/// @param agentId Agent identifier.
		/// @param asymmetricKeys asymmetric keys used to communicate with the Gateway.
		NodeRelay(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory, Crypto::PublicSignature const& gatewaySignature, Crypto::SymmetricKey const& broadcastKey,
			BuildId buildId, AgentId agentId = AgentId::GenerateRandom(), Crypto::AsymmetricKeys const& asymmetricKeys = Crypto::GenerateAsymmetricKeys());

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

		/// Passes provided (most probably an S2X) packet further.
		/// @param packet0 a buffer that contains whole packet.
		/// @param routeId packet's destination.
		virtual void MultiSendPacketFurtherThroughRouteId(ByteView packet0, RouteId routeId);

		/// Called whenever an attached Binder Peripheral wants to send a Command to its Connector Binder.
		/// @param command full Command with arguments.
		/// @param channel Interface that will be used to send the packet.
		void PostCommandToConnector(ByteView command, std::shared_ptr<DeviceBridge> channel) override;

		/// Handler fired when a N2N::InitializeRoute Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresN2N::InitializeRouteQuery&& query) override;

		/// Handler fired when a N2N::InitializeRoute Procedure arrives.
		/// @param query object representing the Query.
		void On(ProceduresS2G::InitializeRouteQuery&& query) override;

		/// Handler fired when a G2X::AddRoute Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresG2X::AddRoute query) override;

		/// Handler Fired N2N::ChannelIdExchangeStep1 Procedure Query arrives.
		/// This query indicates that some relay wants to negotiate joining the network.
		/// @param query object representing the Query.
		void On(ProceduresN2N::ChannelIdExchangeStep1 query) override;

		/// Handler Fired N2N::ChannelIdExchangeStep2 Procedure Query arrives.
		/// This query contains parameters for unique connection. Relay can send initialization query to GateRelay to registration in network.
		/// @param query object representing the Query.
		void On(ProceduresN2N::ChannelIdExchangeStep2 query) override;

		/// Sets the default Device used in communication with the server.
		/// @param gatewayReturnChannel Device to set as a new return channel.
		void SetGatewayReturnChannel(std::shared_ptr<DeviceBridge> const& gatewayReturnChannel);

		/// Sets the default Device used in communication with the server.
		/// @param args Device id stored in byte form.
		void SetGatewayReturnChannel(FSecure::ByteView args);

		/// Returns timestamp to Gateway.
		/// @param args unused.
		void Ping(FSecure::ByteView args);

		/// Gets the default Device used in communication with the server.
		/// @return current Gateway return channel.
		std::shared_ptr<DeviceBridge> GetGatewayReturnChannel() const;

		/// Creates and attaches a new Device.
		/// @param iid address of Device in Relay.
		/// @param deviceNameHash hash to distinguish devices types.
		/// @param isNegotiationChannel true if channel will support negotiation procedure.
		/// @param commandLine buffer containing Device's construction parameters.
		/// @param negotiationClient true if channel will support negotiation procedure, and should start it.
		/// @return newly created Device or null if there was no factory able to process provided command-line.
		/// @throws std::runtime_error if device cannot be created becouse it was not registrated or commandLine is invalid.
		std::shared_ptr<DeviceBridge> CreateAndAttachDevice(DeviceId iid, HashT deviceNameHash, bool isNegotiationChannel, ByteView commandLine, bool negotiationClient = false) override;

		/// Send packet through first interface to gateway, with registration request.
		void InitializeRoute();

		/// Starts procedure of unique channel negotiation.
		/// @param device channel that will perform negotiation.
		void NegotiateChannel(std::shared_ptr<DeviceBridge> const& device);

		/// Handler fired when a G2X::RunCommandOnAgentQuery Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresG2X::RunCommandOnAgentQuery) override;

		/// Handler fired when a G2X::RunCommandOnDeviceQuery Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresG2X::RunCommandOnDeviceQuery) override;

		/// Handler fired when a G2X::DeliverToBinder Procedure Query arrives.
		/// @param query object representing the Query.
		void On(ProceduresG2X::DeliverToBinder query) override;

		/// Inform gateway that new Device was added correctly.
		/// @param device pointer to newly created device.
		void SendNewDeviceNotification(std::shared_ptr<FSecure::C3::Core::DeviceBridge> const& device);

		/// Inform gateway that new Device was added by negotiation process.
		/// @param newDeviceId id of new device in relay.
		/// @param negotiatorId id of device that was used for negotiation.
		/// @param inId negotiated input parameter.
		/// @param outId negotiated output parameter.
		void SendNewNegotiatedChannelNotification(DeviceId newDeviceId, DeviceId negotiatorId, ByteView inId, ByteView outId);

		/// Creates device from provided byte form of arguments @see CreateAndAttachDevice.
		/// @param commandArgs all arguments for CreateAndAttachDevice packed in byte form.
		std::shared_ptr<FSecure::C3::Core::DeviceBridge> RunCommandAddDevice(ByteView commandArgs);

	private:
		std::atomic<DeviceId::UnderlyingIntegerType> m_LastResevedDeviceId = ~(1 << (8 * DeviceId::BinarySize - 1));	///< DeviceId with MSB set are used for deviceId assigned by Node

		std::weak_ptr<DeviceBridge> m_GatewayReturnChannel;																///< Channel used to communicate with the Gateway by default.
		Crypto::PublicSignature m_GatewaySignature;																		///< A public signature used by Network's Gateway to authenticate itself.
		Crypto::PublicKey m_GatewayEncryptionKey;																		///< Gateway's public key (converted from signature) used to encrypt N2G packets.
		Crypto::PublicKey m_MyEncryptionKey;																			///< This is going to be sent to Gateway.
	};
}
