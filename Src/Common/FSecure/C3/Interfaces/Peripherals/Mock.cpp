#include "StdAfx.h"
#include "Mock.h"

#ifdef _DEBUG

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Peripherals::Mock::Mock(ByteView)
	: m_NextMessageTime{ std::chrono::high_resolution_clock::now() }
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Peripherals::Mock::OnCommandFromConnector(ByteView packet)
{
	// Construct a copy of received packet trimmed to 10 characters and add log it.
	Log({ OBF("Mock received: ") + std::string{ packet.begin(), packet.size() < 10 ? packet.end() : packet.begin() + 10 } + OBF("..."), LogMessage::Severity::DebugInformation });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Mock::OnReceiveFromPeripheral()
{
	// Send heart beat every 5s.
	if (m_NextMessageTime > std::chrono::high_resolution_clock::now())
		return {};

	m_NextMessageTime = std::chrono::high_resolution_clock::now() + 5s;
	return  ByteView{ OBF("Beep") };
}

FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Mock::OnRunCommand(ByteView command)
{
	auto commandCopy = command;
	switch (command.Read<uint16_t>())
	{
	case 0:
		return TestErrorCommand(command);
	default:
		return AbstractPeripheral::OnRunCommand(commandCopy);
	}
}

FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Mock::TestErrorCommand(ByteView arg)
{
	GetBridge()->SetErrorStatus(arg.Read<std::string>());
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteView FSecure::C3::Interfaces::Peripherals::Mock::GetCapability()
{
	return R"(
{
	"create":
	{
		"arguments":[]
	},
	"commands":
	[
		{
			"name": "Test command",
			"description": "Set error on connector.",
			"id": 0,
			"arguments":
			[
				{
					"name": "Error message",
					"description": "Error set on connector. Send empty to clean up error"
				}
			]
		}
	]
}
)";
}
#endif // _DEBUG
