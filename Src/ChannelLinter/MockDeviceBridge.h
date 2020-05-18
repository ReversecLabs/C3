#pragma once

#include "Core/QualityOfService.h"

namespace FSecure::C3::Linter
{
	/// Device bridge used to mock its functionality
	class MockDeviceBridge final : public FSecure::C3::AbstractDeviceBridge, public std::enable_shared_from_this<MockDeviceBridge>
	{
	public:
		/// Create Mock device bridge to device
		/// @param device to bridge to
		MockDeviceBridge(std::shared_ptr<Device> device);

		/// Called by Relay just after the Device creation.
		void OnAttach() override;

		/// Detaches the Device.
		void Detach() override;

		/// Notify the relay that this bridge should be closed
		void Close() override;

		/// Callback periodically fired by Relay for Device to update it's state. Might be called from a separate thread. Device should perform all necessary actions and leave as soon as possible.
		void OnReceive() override;

		/// Fired by Channel when a C3 packet arrives.
		/// @param packet full C3 packet.
		void PassNetworkPacket(ByteView packet) override;

		/// Fired by Relay to pass provided C3 packet through the Channel Device.
		/// @param packet full C3 packet.
		void OnPassNetworkPacket(ByteView packet) override;

		/// Called whenever Peripheral wants to send a Command to its Connector Binder.
		/// @param command full Command with arguments.
		void PostCommandToConnector(ByteView command) override;

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

		/// Modifies the duration and jitter of OnReceive() calls. If minUpdateDelayInMs != maxUpdateDelayInMs then update frequency is randomized in range between those values.
		/// @param minUpdateDelayInMs minimum update frequency.
		/// @param maxUpdateDelayInMs maximum update frequency.
		void SetUpdateDelay(std::chrono::milliseconds minUpdateDelayInMs, std::chrono::milliseconds maxUpdateDelayInMs) override;

		/// Sets time span between OnReceive() calls to a fixed value.
		/// @param frequencyInMs frequency of OnReceive() calls.
		void SetUpdateDelay(std::chrono::milliseconds frequencyInMs) override;

		void SetErrorStatus(std::string_view errorMessage) override;
		std::string GetErrorStatus() override;

		/// @returns Bridged device
		std::shared_ptr<FSecure::C3::Device> GetDevice() const;

		/// Send data to through channel.
		/// @param blob - data to send.
		/// @throws std::runtime_error if unable to send data.
		void Send(ByteView blob);

		/// Receive data from channel.
		/// @param minExpectedSize - min number of packets function should return.
		/// @throws std::runtime_error if unable to return vector of required number of full packets.
		std::vector<ByteVector> Receive(size_t minExpectedSize = 1);

	private:
		/// Bridged device
		std::shared_ptr<Device> m_Device;

		/// Handle chunking.
		QualityOfService m_QoS;
	};
}

