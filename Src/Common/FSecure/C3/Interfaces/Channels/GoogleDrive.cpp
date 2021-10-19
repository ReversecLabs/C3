#include "Stdafx.h"
#include "GoogleDrive.h"
#include "Common/FSecure/Crypto/Base64.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::GoogleDrive::GoogleDrive(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [userAgent, ClientId, ClientSecret, RefreshToken, channelName] = arguments.Read<std::string, std::string, std::string, std::string, std::string>();
	m_googledriveObj = FSecure::GoogleDrive{ userAgent, ClientId, ClientSecret, RefreshToken, channelName };
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::GoogleDrive::OnSendToChannel(ByteView data)
{
	// There is a cap on uploads of files >5mb at which point different APIs are required.
	data = data.SubString(0, 5 * 1024 * 1024);
	m_googledriveObj.WriteMessageToFile(m_outboundDirectionName, data);
	return data.size();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::GoogleDrive::OnReceiveFromChannel()
{
	std::vector<ByteVector> ret;
	for (auto& [ts, id] : m_googledriveObj.GetMessagesByDirection(m_inboundDirectionName))
	{
		ret.push_back(m_googledriveObj.ReadFile(id));
		m_googledriveObj.DeleteFile(id);
	}

	return ret;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::GoogleDrive::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCopy is needed for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		UploadFile(command);
		return {};
	case 1:
		DeleteAllFiles();
		return {};
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

void FSecure::C3::Interfaces::Channels::GoogleDrive::UploadFile(ByteView args)
{
	m_googledriveObj.UploadFile(args.Read<std::string>());
}


void FSecure::C3::Interfaces::Channels::GoogleDrive::DeleteAllFiles()
{
	m_googledriveObj.DeleteAllFiles();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::GoogleDrive::GetCapability()
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
				"description": "The User-Agent header to set. Warning: adding user agent header of web browser, can cause site security provider to block access to api, and prevent channel from funcionating."
			},
			{
				"type": "string",
				"name": "Client ID",
				"min": 1,
				"description": "Client ID for GoogleDrive's API"
			},
			{
				"type": "string",
				"name": "Client Secret",
				"min": 1,
				"description": "Client Secret for GoogleDrive's API"
			},
			{
				"type": "string",
				"name": "Refresh token",
				"min": 1,
				"description": "This token is used to retrieve an access token for GoogleDrive's API"
			},
			{
				"type": "string",
				"name": "Folder name",
				"min": 4,
				"randomize": true,
				"description": "Folder to create for channel"
			}
		]
	},
	"commands": 
	[
		{
			"name": "Upload File from Relay",
			"id": 0,
			"description": "Upload file from host running Relay directly to GoogleDrive (150mb max.)",
			"arguments": 
			[
				{
                    "type" : "string",
					"name": "Remote Filepath",
					"description" : "Path to upload."
				}
			]
		},
		{
			"name": "Remove All Files",
			"id": 1,
			"description": "Delete channel folder and all files within it.",
			"arguments": []
		}
	]
}
)_";
}

