#pragma once

#include "Common/MWR/C3/Internals/BackendCommons.h"
#include "Identifiers.h"
#include "Common/MWR/C3/Internals/Interface.h"
#include "QualityOfService.h"

// Forward declarations.
namespace MWR::C3
{
	struct Device;
	namespace Core
	{
		struct Relay;
	}
}

namespace MWR::C3::Core
{
	/// PIMPL for Device type.
	struct DeviceBridge : AbstractDeviceBridge, std::enable_shared_from_this<DeviceBridge>
	{
		/// Public constructor, used by Relays.
		/// @param relay "parent" Relay this Device is being attached to.
		/// @param did preferred Identifier.
		/// @param typeNameHash Device's Name hash
		/// @param device the Device this object binds Relay with.
		/// @param isNegotiationChannel indicates that device is channel, and will be used in negotiation procedure.
		/// @param isSlave indicates that device is negotiation channel, and will be requesting to join the network.
		/// @param args original arguments of negotiation channel, used to create negotiated channels.
		DeviceBridge(std::shared_ptr<Relay>&& relay, DeviceId did, HashT typeNameHash, std::shared_ptr<Device>&& device, bool isNegotiationChannel = false, bool isSlave = false, ByteVector args = ByteVector{});

		/// Called by Relay just after the Device creation.
		void OnAttach() override;

		/// Detaches the Device.
		void Detach() override;

		/// Callback periodically fired by Relay for Device to update it's state. Might be called from a separate thread. Device should perform all necessary actions and leave as soon as possible.
		void OnReceive() override;

		/// Fired by Channel when a C3 packet arrives.
		/// @param packet full C3 packet.
		void PassNetworkPacket(ByteView packet) override;

		/// Fired by Relay to pass provided C3 packet through the Channel Device.
		/// @param packet full C3 packet.
		void OnPassNetworkPacket(ByteView packet) override;

		/// Called whenever an attached Peripheral wants to send a Command to its Connector Binder.
		/// @param command full Command with arguments.
		void PostCommandToConnector(ByteView packet) override;

		/// Fired by Relay to pass by provided Command from Connector.
		/// @param command full Command with arguments.
		void OnCommandFromConnector(ByteView command) override;

		/// Runs Device's Command.
		/// @param command Device's Command to run.
		/// @return Command result.
		ByteVector RunCommand(ByteView command) override;

		/// Tells Device's type name.
		/// @return A buffer with Device's description.
		ByteVector WhoAreYou() override;

		/// Logs a message. Used by internal mechanisms to report errors, warnings, informations and debug messages.
		/// @param message information to log.
		void Log(LogMessage const& message) override;

		/// Device ID getter.
		/// @return Device identifier.
		DeviceId GetDid() const;

		/// Tells whether Device is a Channel or not.
		/// @return true if Device is a Channel.
		bool IsChannel() const;

		/// Informs if device can be used for negotiation.
		/// @returns true if device is negotiation channel, false if it is normal channel, or peripheral.
		bool IsNegotiationChannel() const;

		/// Get original channel parameters.
		/// @returns ByteView view of parameters.
		/// @remarks should be called only for negotiation channels.
		ByteView GetChannelParameters() const { return m_NonNegotiatiedArguments; }

		/// Get channel input Id parameters.
		/// @returns ByteView view of input Id.
		/// @remarks should be called only for negotiation channels.
		ByteView GetInputId() const { return m_InputId; }

		/// Get channel output Id parameters.
		/// @returns ByteView view of output Id.
		/// @remarks should be called only for negotiation channels.
		ByteView GetOutputId() const { return m_OutpuId; }

		/// Type ID getter.
		/// @return Device's Name hash.
		HashT GetTypeNameHash() const;

		/// Creates the receiving thread.
		virtual void StartUpdatingInSeparateThread();

		/// Modifies the duration and jitter of OnReceive() calls. If minUpdateDelayInMs != maxUpdateDelayInMs then update frequency is randomized in range between those values.
		/// @param minUpdateDelayInMs minimum update frequency.
		/// @param maxUpdateDelayInMs maximum update frequency.
		void SetUpdateDelay(std::chrono::milliseconds minUpdateDelayInMs, std::chrono::milliseconds maxUpdateDelayInMs) override;

		/// Sets time span between OnReceive() calls to a fixed value.
		/// @param frequencyInMs frequency of OnReceive() calls.
		void SetUpdateDelay(std::chrono::milliseconds frequencyInMs) override;

		/// "Parent" Relay getter.
		/// @return Relay this Device is attached to.
		std::shared_ptr<Relay> GetRelay() const;

		/// Set error on device.
		/// @param errorMessage text of error. Set empty to remove error.
		void SetErrorStatus(std::string_view errorMessage) override;

		/// Get error string.
		std::string GetErrorStatus() override;

	protected:
		/// Device object getter.
		/// @return Device this object binds Relay with.
		std::shared_ptr<Device> GetDevice() const;

	private:
		bool m_IsAlive = true;																							///< False if detached and about to be destroyed.
		const bool m_IsNegotiationChannel = false;																		///< Indicates that device is channel, and will be used in negotiation procedure.
		const bool m_IsSlave;																							///< Indicates that device is negotiation channel, and will be requesting to join the network.
		ByteVector m_NonNegotiatiedArguments;																			///< Arguments common for channels, both negotiation and normal.
		ByteVector m_InputId;																							///< Input Id of channel. Use only in negotiation procedure.
		ByteVector m_OutpuId;																							///< Output Id of channel. Use only in negotiation procedure.
		const DeviceId m_Did;																							///< Identifier. Device address on Relay.
		const HashT m_TypeNameHash;																						///< Hash value of the actual Device's name.

		QualityOfService m_QoS;																							///< Quality of Service object.
		std::shared_ptr<Relay> m_Relay;																					///< Relay this Device is attached to.
		std::shared_ptr<Device> m_Device;																				///< Device this object binds Relay with.
		std::string m_Error;																							///< String with error text. No error if empty.
		std::mutex m_ProtectWriteInConcurrentThreads;																	///< Allow only one thread to Write to device at one time.
	};
}
