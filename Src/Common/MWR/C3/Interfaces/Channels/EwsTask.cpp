#include "StdAfx.h"
#include "EwsTask.h"
#include "Common/EWS/ews.hpp"
#include "Common/MWR/Crypto/Base32.h"
#include "Common/MWR/Crypto/Base64.h"


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Channels::EwsTask::EwsTask(ByteView arguments)
	: m_InboundDirectionName{ ByteView{arguments.Read<ByteVector>()} } // TODO ByteArray to std::string conversion.
	, m_OutboundDirectionName{ ByteView{arguments.Read<ByteVector>()} }
	, m_EwsServerUri{ arguments.Read<std::string>() }
	, m_EwsUserName{ arguments.Read<std::string>() }
	, m_EwsPassword{ arguments.Read<std::string>() }
{
	// Initialize EWS library.
	ews::set_up();

	// Check if additional flag to remove all tasks was provided.
	if (arguments.Read<uint8_t>())
		RemoveAllTasks({});
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::C3::Interfaces::Channels::EwsTask::~EwsTask()
{
	// Deinitialize EWS library.
	ews::tear_down();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t MWR::C3::Interfaces::Channels::EwsTask::OnSendToChannel(ByteView packet)
{
	// Create an EWS service object.
	auto ewsService = ews::service(m_EwsServerUri, ews::basic_credentials(m_EwsUserName, m_EwsPassword));

	// Create and send a task with subject = OutboundDirectionName.
	auto task = ews::task();
	task.set_subject(m_OutboundDirectionName);
	task.set_body(ews::body(cppcodec::base64_rfc4648::encode(&packet.front(), packet.size())));
	ewsService.create_item(task);

	Log({ OBF("OnSend() called for EwsTask carrying ") + std::to_string(packet.size()) + OBF(" bytes"), LogMessage::Severity::DebugInformation });
	return packet.size();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Channels::EwsTask::OnReceiveFromChannel()
{
	// Create an EWS service object and the return buffer.
	auto ewsService = ews::service(m_EwsServerUri, ews::basic_credentials(m_EwsUserName, m_EwsPassword));
	ByteVector retPacket;

	// Get tasks from server
	std::vector<ews::item_id> items;
	try
	{
		items = ewsService.find_item(ews::distinguished_folder_id(ews::standard_folder::tasks),
									 ews::contains(ews::item_property_path::subject, m_InboundDirectionName.c_str(),
									 ews::containment_mode::substring, ews::containment_comparison::ignore_case));
	}
	catch (ews::exchange_error & exception)
	{
		Log({ OBF("EWS error ") + std::to_string(static_cast<unsigned>(exception.code())) + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
	}

	// Process all task IDs (fetch only those with the correct m_InboundDirectionName)
	for (auto&& id : items)
		try
		{
			// Check if message is addressed to this Interface instance.
			if (auto task = ewsService.get_task(id); task.get_subject() == m_InboundDirectionName)
			{
				// Decode message's body and delete the task.
				retPacket = cppcodec::base64_rfc4648::decode(task.get_body().content());
				ewsService.delete_task(std::move(task));
				break;
			}
		}
		catch (ews::exchange_error & exception)
		{
			if (exception.code() != ews::response_code::error_item_not_found)		//< Task was removed between taking ID and reading. It is not an error.
				Log({ OBF("EWS error ")+ std::to_string(static_cast<unsigned>(exception.code())) + OBF(" when processing task #") + id.id() + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
		}
		catch (const cppcodec::parse_error & exception)
		{
			Log({ OBF("Error decoding task #") + id.id() + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
		}
		catch (std::exception & exception)
		{
			Log({ OBF("Caught a std::exception when processing task #") + id.id() + OBF(" : ") + exception.what(), LogMessage::Severity::Error });
		}

		return retPacket;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteVector MWR::C3::Interfaces::Channels::EwsTask::RemoveAllTasks(ByteView)
{
	Log({ OBF("Removing all existing EWS tasks."), LogMessage::Severity::Information });

	// Iterate through the list of tasks, removing each of them one by one.
	auto ewsService = ews::service(m_EwsServerUri, ews::basic_credentials(m_EwsUserName, m_EwsPassword));
	for (auto&& id : ewsService.find_item(ews::distinguished_folder_id(ews::standard_folder::tasks), ews::is_equal_to(ews::task_property_path::is_complete, false)))
		ewsService.delete_task(ewsService.get_task(id));

	return {};
}

MWR::ByteVector MWR::C3::Interfaces::Channels::EwsTask::OnRunCommand(ByteView command)
{
	auto commandCopy = command; //each read moves ByteView. CommandCoppy is needed  for default.
	switch (command.Read<uint16_t>())
	{
		case 0:
			return RemoveAllTasks(command);
		default:
			return AbstractChannel::OnRunCommand(commandCopy);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
MWR::ByteView MWR::C3::Interfaces::Channels::EwsTask::GetCapability()
{
	return R"(
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
				"name": "Uri",
				"min": 1,
				"description": "Uri of EWS server"
			},
			{
				"type": "string",
				"name": "Username",
				"min": 1,
				"description": "Username used to sign in"
			},
			{
				"type": "string",
				"name": "Password",
				"description": "Password used to sign in"
			},
			{
				"type": "boolean",
				"name": "Remove all task",
				"defaultValue": true,
				"description": "Clearing old tasks from server before starting communication may increase bandwidth"
			}

		]
	},
	"commands":
	[
		{
			"name": "Remove all tasks",
			"id": 0,
			"description": "Clearing old tasks from server may increase bandwidth",
			"arguments": []
		}
	]
}
)";
}
