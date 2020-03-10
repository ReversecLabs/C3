#pragma once

#include "Distributor.h"
#include "Common/FSecure/C3/Internals/InterfaceFactory.h"

namespace FSecure::C3::Core
{
	/// Last base layer class for both Relay types.
	struct Relay : Distributor, FSecure::C3::Relay
	{
		/// Destructor
		virtual ~Relay() = default;

		/// Called whenever an attached Binder Peripheral wants to send a Command to its Connector Binder.
		/// @param command full Command with arguments.
		/// @param sender Interface that is sending the Command.
		virtual void PostCommandToConnector(ByteView command, std::shared_ptr<DeviceBridge> sender) = 0;
		AgentId GetAgentId() const { return m_AgentId; }
		BuildId GetBuildId() const { return m_BuildId; }

		/// Detaches an Device. This operation leads to (delayed) destruction of the Device.
		/// @param iidOfDeviceToDetach ID of the Device to detach.
		/// @throw std::invalid_argument on an attempt of removal of a non-existent Device.
		virtual void DetachDevice(DeviceId const& iidOfDeviceToDetach);

	protected:
		using Distributor::On;

		/// A protected constructor. @see Distributor::Distributor.
		/// @param callbackOnLog callback fired whenever a new Log entry is being added.
		/// @param interfaceFactory reference to Interface factory.
		/// @param decryptionKey Relay's private asymmetric key.
		/// @param broadcastKey Network's symmetric key.
		/// @param buildId Build identifier.
		/// @param agentId Agent identifier.
		Relay(LoggerCallback callbackOnLog, InterfaceFactory& interfaceFactory, Crypto::PrivateKey const& decryptionKey, Crypto::SymmetricKey const& broadcastKey, BuildId buildId, AgentId agentId = AgentId::GenerateRandom());

		/// Add a new Device.
		/// @param iid preferred Identifier.
		/// @param DeviceNameHash hash value of Device's name.
		/// @param commandLine buffer containing Device's construction parameters.
		/// @return newly created Device.
		/// @throws std::runtime_error if couldn't find factory for specified Device name hash or other exceptions if factory was unable to process provided command-line.
		virtual std::shared_ptr<DeviceBridge> CreateAndAttachDevice(DeviceId iid, HashT deviceNameHash, bool isNegotiationChannel, ByteView commandLine, bool negotiationClient = false);

		/// Attaches provided Device to the Relay.
		/// @param device provided Device.
		/// @return same as device argument.
		virtual std::shared_ptr<DeviceBridge> AttachDevice(std::shared_ptr<FSecure::C3::Core::DeviceBridge> device);

		/// Close Relay (command handler)
		virtual void Close();

		/// Create route (command handler)
		/// @param args - packed arguments of route to create
		virtual void CreateRoute(ByteView args);

		/// Remove route (command handler)
		/// @param args - packed arguments of route to remove
		virtual void RemoveRoute(ByteView args);

		/// Finds attached Device from Device ID hex text.
		/// @param did ID of the Device to find.
		/// @return Device pointer to the Device if found or null.
		std::shared_ptr<DeviceBridge> FindDevice(DeviceId did);

		/// Waits for Relay to be terminated internally by a C3 API Command (e.g. from WebController).
		void Join() override;

		SafeSmartPointerContainer<std::weak_ptr<DeviceBridge>> m_Devices;												///< Container for all attached Devices.
		const BuildId m_BuildId;																						///< An unique identifier for the Relay's binary setup (Build identifier).
		AgentId m_AgentId;																								///< A run-time generated, unique identifier for this Relay's instance.
		InterfaceFactory& m_InterfaceFactory;																			///< Object responsible for crating new Devices.
	};
}
