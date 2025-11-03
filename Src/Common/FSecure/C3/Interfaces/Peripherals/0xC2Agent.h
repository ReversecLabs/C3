#pragma once

#include <optional>
#include "Common/FSecure/WinTools/Pipe.h"

/// Forward declaration of Connector associated with implant.
/// Connectors implementation is only available on GateRelay, not NodeRelays.
/// Declaration must be identical to Connector definition. Namespace or struct/class mismatch will make Peripheral unusable.
namespace FSecure::C3::Interfaces::Connectors { struct OhxC2; }

namespace FSecure::C3::Interfaces::Peripherals
{
	/// Class representing OhxC2Agent stager.
	struct OhxC2Agent : public Peripheral<OhxC2Agent, Connectors::OhxC2>
	{
	public:
		/// Public constructor.
		/// @param arguments view of arguments prepared by Connector.
		OhxC2Agent(ByteView arguments);

		/// Destructor
		virtual ~OhxC2Agent();

		/// Sending callback implementation.
		/// @param packet to send to the Implant.
		void OnCommandFromConnector(ByteView packet) override;

		/// Callback that handles receiving from the outside of the C3 network (Cobalt Strike OhxC2Agent).
		/// @returns ByteVector data received from OhxC2Agent.
		ByteVector OnReceiveFromPeripheral() override;

		/// Return json with commands.
		/// @return Capability description in JSON format.
		static const char* GetCapability();

		/// Close Peripheral OhxC2Agent
		/// Calls superclass Close and prepares to exit without deadlocking
		void Close() override;


	private:
		/// Check if data is no-op.
		/// @return true if data is no-op, false otherwise.
		static bool IsNoOp(ByteView data);

		/// Object used to communicate with OhxC2Agent.
		/// Optional is used to perform many trails of staging in constructor.
		/// Must contain object if constructor call was successful.
		std::optional<WinTools::AlternatingPipe> m_Pipe;

		/// Send queue from TeamServer
		std::deque<ByteVector> m_SendQueue;

		/// Used to exit
		bool m_Close = false;

		/// Used to get a handle to the OhxC2Agent thread
		FSecure::WinTools::InjectionBuffer m_OhxC2Agent;
	};
}
