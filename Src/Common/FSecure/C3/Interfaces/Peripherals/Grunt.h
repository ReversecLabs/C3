#pragma once

#include <optional>
#include <metahost.h>

//For loading of CLR
#pragma comment(lib, "mscoree.lib")
#import "mscorlib.tlb" raw_interfaces_only high_property_prefixes("_get", "_put", "_putref") rename("ReportEvent", "InteropServices_ReportEvent") auto_rename
using namespace mscorlib;

#include "Common/FSecure/WinTools/Pipe.h"

/// Forward declaration of Connector associated with implant.
/// Connectors implementation is only available on GateRelay, not NodeRelays.
/// Declaration must be identical to Connector definition. Namespace or struct/class mismatch will make Peripheral unusable.
namespace FSecure::C3::Interfaces::Connectors { struct Covenant; }

namespace FSecure::C3::Interfaces::Peripherals
{
	/// Class representing Grunt stager.
	struct Grunt : public Peripheral<Grunt, Connectors::Covenant>
	{
	public:
		/// Public constructor.
		/// @param arguments view of arguments prepared by Connector.
		Grunt(ByteView arguments);

		/// Sending callback implementation.
		/// @param packet to send to the Implant.
		void OnCommandFromConnector(ByteView packet) override;

		/// Callback that handles receiving from the outside of the C3 network.
		/// @returns ByteVector data received from beacon.
		ByteVector OnReceiveFromPeripheral() override;

		/// Return json with commands.
		/// @return ByteView Commands description in JSON format.
		static ByteView GetCapability();
		
		/// Close peripheral Grunt
		/// Calls superclass CLose and prepares to exit without deadlocking
		void Close() override;

	private:

		/// Object used to communicate with Grunt.
		/// Optional is used to perform many trails of staging in constructor.
		/// Must contain object if constructor call was successful.
		std::optional<WinTools::AlternatingPipe> m_Pipe;

		/// Used to synchronize access to underlying implant.
		std::mutex m_Mutex;

		/// Used to synchronize read/write.
		std::condition_variable m_ConditionalVariable;

		/// Used to support beacon chunking data.
		bool m_ReadingState = true;

		bool m_Close = false;
	};
}
