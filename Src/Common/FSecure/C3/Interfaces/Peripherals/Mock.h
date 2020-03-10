#pragma once

#ifdef _DEBUG

/// Forward declaration of Connector associated with implant.
/// Connectors implementation is only available on GateRelay, not NodeRelays.
/// Declaration must be identical to Connector definition. Namespace or struct/class mismatch will make Peripheral unusable.
namespace FSecure::C3::Interfaces::Connectors { class MockServer; }

namespace FSecure::C3::Interfaces::Peripherals
{
	/// Class representing mock implant.
	class Mock : public Peripheral<Mock, Connectors::MockServer>
	{
	public:
		/// Public Constructor.
		/// @param ByteView unused.
		Mock(ByteView);

		/// Destructor
		virtual ~Mock() = default;

		/// Sending callback implementation.
		/// @param packet to send to the Implant.
		void OnCommandFromConnector(ByteView packet) override;

		/// Callback that handles receiving from the Mock.
		/// @returns ByteVector data received.
		ByteVector OnReceiveFromPeripheral() override;

		/// Return json with commands.
		/// @return Capability description in JSON format.
		static const char* GetCapability();

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return ByteVector command result.
		ByteVector OnRunCommand(ByteView command) override;

	private:
		/// Example of internal command of peripheral. Must be described in GetCapability, and handled in OnRunCommand
		/// @param arg all arguments send to method.
		/// @returns ByteVector response for command.
		ByteVector TestErrorCommand(ByteView arg);

		/// Used to delay receiving data from mock implementaion.
		std::chrono::time_point<std::chrono::steady_clock> m_NextMessageTime;
	};
}
#endif // _DEBUG
