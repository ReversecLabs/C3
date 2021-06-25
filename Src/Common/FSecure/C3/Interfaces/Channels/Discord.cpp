#include "Stdafx.h"
#include "Discord.h"
#include "Common/FSecure/Crypto/Base64.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Discord::Discord(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [userAgent, discordToken, channelName, guildId ] = arguments.Read<std::string, std::string, std::string, std::string>();
	m_discordObj = FSecure::Discord{ userAgent, discordToken, channelName, guildId };
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Discord::OnSendToChannel(ByteView data)
{
	//Begin by creating a message where we can write the data to in a thread, both client and server ignore this message to prevent race conditions
	std::string messageId = m_discordObj.WriteMessage(m_outboundDirectionName + OBF(":writing"));

	//this is more than 30 messages, send it as a file (we do this infrequently as file uploads restricted to 20 per minute).
	//Using file upload for staging (~88 messages) is a huge improvement over sending actual replies.
	size_t actualPacketSize = 0;
	if (data.size() > 6'000)
	{
		m_discordObj.UploadFile(cppcodec::base64_rfc4648::encode<ByteVector>(data.data(), data.size()), messageId);
		actualPacketSize = data.size();
	}
	else
	{
		//Write the full data into the thread. This makes it alot easier to read in onRecieve as slack limits messages to 40k characters.
		constexpr auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(2'000);
		actualPacketSize = std::min(maxPacketSize, data.size());
		auto sendData = data.SubString(0, actualPacketSize);

		m_discordObj.WriteReply(cppcodec::base64_rfc4648::encode(sendData.data(), sendData.size()), messageId);
	}

	//Update the original first message with "C2S||S2C:Done" - these messages will always be read in onRecieve.
	std::string message = m_outboundDirectionName + OBF(":Done");

	m_discordObj.UpdateMessage(message, messageId);
	return actualPacketSize;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::Discord::OnReceiveFromChannel()
{
	auto messages = m_discordObj.GetMessagesByDirection(m_inboundDirectionName + OBF(":Done"));

	std::vector<ByteVector> ret;
	//Read the messages in reverse order (which is actually from the oldest to newest)
	//Avoids old messages being left behind.
	for (std::vector<std::string>::reverse_iterator id = messages.rbegin(); id != messages.rend(); ++id)
	{

		auto replies = m_discordObj.ReadReplies(*id);
		std::vector<std::string> replyIds;

		std::string message;

		//Get all of the messages from the replies.
		for (auto&& reply : replies)
		{
			message.append(reply.second);
			replyIds.push_back(std::move(reply.first)); //get all of the ids for later deletion
		}

		//Base64 decode the entire message
		auto relayMsg = cppcodec::base64_rfc4648::decode(message);
		m_discordObj.DeleteMessage(*id);	//delete the message
		DeleteReplies(replyIds); //delete the replies.
		ret.emplace_back(std::move(relayMsg));
	}
	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Discord::DeleteReplies(std::vector<std::string> const& replyIds)
{
	for (auto&& id : replyIds)
		m_discordObj.DeleteMessage(id);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Discord::DeleteChannel()
{
	m_discordObj.DeleteChannel();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Discord::DeleteAllMessages()
{
	m_discordObj.DeleteAllMessages();
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::Discord::OnRunCommand(ByteView command)
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
const char* FSecure::C3::Interfaces::Channels::Discord::GetCapability()
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
				"name": "Discord bot token",
				"min": 1,
				"description": "This token is what channel needs to interact with Discord's API"
			},
			{
				"type": "string",
				"name": "Channel name",
				"min": 4,
				"randomize": true,
				"description": "Name of Discord's channel used by api"
			},
			{
				"type": "string",
				"name": "Guild Id",
				"min": 4,
				"description": "ID of the Guild/Server to be used"
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

