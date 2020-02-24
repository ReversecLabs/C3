#pragma once

#include <optional>
#include "Common/MWR/WinTools/Pipe.h"

/// Forward declaration of Connector associated with implant.
/// Connectors implementation is only available on GateRelay, not NodeRelays.
/// Declaration must be identical to Connector definition. Namespace or struct/class mismatch will make Peripheral unusable.
namespace MWR::C3::Interfaces::Connectors { struct TeamServer; }

namespace MWR::C3::Interfaces::Peripherals
{
	/// Class representing Beacon stager.
	struct Beacon : public Peripheral<Beacon, Connectors::TeamServer>
	{
	public:
		/// Public constructor.
		/// @param arguments view of arguments prepared by Connector.
		Beacon(ByteView arguments);

		/// Destructor
		virtual ~Beacon();

		/// Sending callback implementation.
		/// @param packet to send to the Implant.
		void OnCommandFromConnector(ByteView packet) override;

		/// Callback that handles receiving from the outside of the C3 network (Cobalt Strike Beacon).
		/// @returns ByteVector data received from beacon.
		ByteVector OnReceiveFromPeripheral() override;

		/// Return json with commands.
		/// @return Capability description in JSON format.
		static const char* GetCapability();

		/// Close Peripheral Beacon
		/// Calls superclass Close and prepares to exit without deadlocking
		void Close() override;


	private:
		/// Check if data is no-op.
		/// @return true if data is no-op, false otherwise.
		static bool IsNoOp(ByteView data);

		/// Object used to communicate with beacon.
		/// Optional is used to perform many trails of staging in constructor.
		/// Must contain object if constructor call was successful.
		std::optional<WinTools::AlternatingPipe> m_Pipe;

		/// Used to synchronize access to underlying implant.
		std::mutex m_Mutex;

		/// Used to synchronize read/write.
		std::condition_variable m_ConditionalVariable;

		/// Used to support beacon chunking data.
		bool m_ReadingState = true;

		/// Used to exit
		bool m_Close = false;

		/// A handle to a beacon thread
		HANDLE m_BeaconThread = INVALID_HANDLE_VALUE;
	};
}
