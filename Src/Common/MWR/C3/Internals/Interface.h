#pragma once

#include "BackendCommons.h"

namespace MWR::C3
{
	template<typename BridgeT>
	struct Interface
	{
		/// Called by Relay just after Device creation.
		/// @param bridge the Shell-Core bridge object bound to this Device.
		virtual void OnAttach(std::shared_ptr<BridgeT> const& bridge);

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		virtual ByteVector OnRunCommand(ByteView command);

		/// Tells Device's (dynamic) capability.
		/// @return A buffer with Device's status and description.
		virtual ByteVector OnWhoAmI() { return {}; }

	protected:
		/// Logs a message. Used by internal mechanisms to report errors, warnings, information and debug messages.
		/// @param message log entry to add.
		virtual void Log(LogMessage const& message);

		/// Detaches from Relay (which leads to destruction of the Device).
		virtual void Detach();

		/// Shell-Core Bridge getter.
		/// @return Bridge object if the Device is attached or null.
		virtual std::shared_ptr<BridgeT> GetBridge() const;

	private:
		std::weak_ptr<BridgeT> m_Bridge;																				///< Shell-Core Bridge (PIMPL).
		std::vector<LogMessage> m_PreLog;																				///< Before the Device gets connected to the Relay, this vector contains all the Log messages.
	};

	/// An abstract structure representing all Devices - Implants, Channels, etc.
	struct Device : Interface<AbstractDeviceBridge>, std::enable_shared_from_this<Device>
	{
		/// Callback periodically fired by Relay for Device to update itself. Might be called from a separate thread. The Device should perform all necessary actions and leave as soon as possible.
		virtual void OnReceive() = 0;

		/// Called every time Relay wants to send a packet through this Channel Device. Should always be called from the same thread for every sender (so it would be safe to use thread_local vars).
		/// @param blob buffer containing data to send.
		/// @remarks this method is used only to pass internal (C3) packets through the C3 network, thus it won't be called for any other types of Devices than Channels.
		virtual size_t  OnSendToChannel(ByteView packet) = 0;

		/// Fired by Relay to pass by provided Command from Connector.
		/// @param command full Command with arguments.
		virtual void OnCommandFromConnector(ByteView command) = 0;

		/// Tells whether Device is a Channel or not.
		/// @return true if Device is a Channel.
		virtual bool IsChannel() const { return false; }

		/// Modifies the duration and jitter of OnReceive() calls. If minUpdateDelayInMs != maxUpdateDelayInMs then update frequency is randomized in range between those values.
		/// @param minUpdateDelayInMs minimum update frequency.
		/// @param maxUpdateDelayInMs maximum update frequency.
		virtual void SetUpdateDelay(std::chrono::milliseconds minUpdateDelayInMs, std::chrono::milliseconds maxUpdateDelayInMs);

		/// Sets time span between OnReceive() calls to a fixed value.
		/// @param frequencyInMs frequency of OnReceive() calls.
		virtual void SetUpdateDelay(std::chrono::milliseconds frequencyInMs);

		/// Gets update frequency. If min and max variables have different values then generates random value in their range.
		virtual std::chrono::milliseconds GetUpdateDelay() const;

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

	protected:
		/// Close device.
		virtual void Close();

		mutable std::mutex m_UpdateDelayMutex;																		///< Mutex to synchronize changes in frequency update members.
		std::chrono::milliseconds m_MinUpdateDelay, m_MaxUpdateDelay;											///< Receive loop moderator (if m_MaxUpdateDelayJitter != m_MinUpdateDelay. then update frequency is randomized in range between those values).
	};

	/// An abstract structure representing all Channels.
	struct AbstractChannel : Device
	{
		/// Callback that is periodically called for every Device to update itself. Might be called from a separate thread. The Device should perform all necessary actions and leave as soon as possible.
		/// @return ByteVector that contains a single packet retrieved from Channel.
		virtual ByteVector OnReceiveFromChannel() = 0;

		/// Tells that this Device type is a Channel.
		bool IsChannel() const override { return true; }

	private:
		/// Callback periodically fired by Relay for Device to update itself. Might be called from a separate thread. The Device should perform all necessary actions and leave as soon as possible.
		void OnReceive() override final;

		/// Fired by Relay to pass by provided Command from Connector, which is illegal for Channels (and that's why this method unconditionally throws std::logic_error).
		/// @throw This method unconditionally throws std::logic_error.
		void OnCommandFromConnector(ByteView) override final
		{
			throw std::logic_error{ OBF("Received a Command from a Connector sent to a Channel.") };
		}
	};

	/// An abstract structure representing all Peripherals.
	struct AbstractPeripheral : Device
	{
		/// Callback that is periodically called for every Device to update itself. Might be called from a separate thread. The Device should perform all necessary actions and leave as soon as possible.
		/// @return ByteVector that contains a single Command retrieved from Peripheral.
		virtual ByteVector OnReceiveFromPeripheral() = 0;

	private:
		/// Callback periodically fired by Relay for Device to update itself. Might be called from a separate thread. The Device should perform all necessary actions and leave as soon as possible.
		void OnReceive() override final;

		/// This method unconditionally throws std::logic_error as calling it is illegal (Peripherals are not a Channels). @see DeviceDevice::OnSendToChannel.
		/// @throw This method unconditionally throws std::logic_error.
		size_t OnSendToChannel(ByteView) override final
		{
			throw std::logic_error{ OBF("Tried to send a C3 packet through a Peripheral.") };
		}
	};

	/// Abstract base for all Connectors.
	struct AbstractConnector : Interface<AbstractConnectorBridge>, std::enable_shared_from_this<AbstractConnector>
	{
		/// Fired by Relay to pass by provided Command from Binder Peripheral.
		/// @param binderId Identifier of Peripheral who sends the Command.
		/// @param command full Command with arguments.
		virtual void OnCommandFromBinder(ByteView binderId, ByteView command) = 0;

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		virtual ByteVector PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64) { return data; }

	protected:
		/// Close Connector.
		virtual void TurnOff();
	};
}

// Include template's implementation.
#include "Interface.hxx"
