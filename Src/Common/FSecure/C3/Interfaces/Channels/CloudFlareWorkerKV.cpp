#include "Stdafx.h"
#include "CloudFlareWorkerKV.h"
#include "Common/FSecure/Crypto/Base64.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::CloudFlareWorkerKV::CloudFlareWorkerKV(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [userAgent, accountId, token, namespaceName] = arguments.Read<std::string, std::string, std::string, std::string>();
	m_workerObj = FSecure::WorkerKV{ userAgent, accountId, token, namespaceName };
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::CloudFlareWorkerKV::OnSendToChannel(ByteView data)
{
	// There is a cap on key value lengths >25mb
	size_t actualPacketSize = 0;
	constexpr auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(25 * 1024 * 1024);
	actualPacketSize = std::min(maxPacketSize, data.size());
	auto sendData = data.SubString(0, actualPacketSize);

	m_workerObj.WriteToKeyValue(m_outboundDirectionName, cppcodec::base64_rfc4648::encode(sendData.data(), sendData.size()));

	return actualPacketSize;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::CloudFlareWorkerKV::OnReceiveFromChannel()
{
	std::vector<ByteVector> ret;
	for (auto& [ts, id] : m_workerObj.GetMessagesByDirection(m_inboundDirectionName))
	{
		ret.push_back(cppcodec::base64_rfc4648::decode(m_workerObj.ReadKeyValue(id)));
		m_workerObj.DeleteKey(id);
	}

	return ret;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::CloudFlareWorkerKV::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCopy is needed  for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		DeleteNamespace();
		return {};
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

void FSecure::C3::Interfaces::Channels::CloudFlareWorkerKV::DeleteNamespace()
{
	m_workerObj.DeleteNamespace();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::CloudFlareWorkerKV::GetCapability()
{
	return R"_(
{
	"create":
	{
		"arguments":
		[
			[
				{
					"type": "string",
					"name": "Input ID",
					"min": 4,
					"randomize": true,
					"description": "Used to distinguish packets for the channel"
				},
				{
					"type": "string",
					"name": "Output ID",
					"min": 4,
					"randomize": true,
					"description": "Used to distinguish packets from the channel"
				}
			],
			{
				"type": "string",
				"name": "User-Agent Header",
				"min": 1,
				"defaultValue": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
				"description": "The User-Agent header to set"
			},
			{
				"type": "string",
				"name": "CloudFlare Account ID",
				"min": 1,
				"description": "This is your CloudFlare Account ID"
			},
			{
				"type": "string",
				"name": "CloudFlare API token",
				"min": 1,
				"description": "This token is what channel needs to interact with WorkerKV's API"
			},
			{
				"type": "string",
				"name": "Namespace name",
				"min": 4,
				"randomize": true,
				"description": "Namespace to create for channel"
			}
		]
	},
	"commands":
	[
		{
			"name": "Delete Namespace",
			"id": 0,
			"description": "Delete channel namespace and all values within it.",
			"arguments": []
		}
	]
}
)_";
}
