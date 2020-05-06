#pragma once

#include "Common/json/json.hpp"
#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/Constants.h"

using json = nlohmann::json; //for easy parsing of json API: https://github.com/nlohmann/json

namespace FSecure
{
	class AsanaApi
	{

	public:
		/// Default constructor.
		AsanaApi() = default;

		/// Constructor for the Asana Api class.
		/// @param token - the personal authentication token generated in Asana
		/// @param projectId - ID of the project to post tasks into
		AsanaApi(std::string const& token, std::string const& projectId, std::string const& inboundDirectionName, std::string const& outboundDirectionName);

		/// Create an Asana task
		/// @param taskName - Name of the new task
		/// @param body - Text to put in the "notes" field (field 'Description' in the Web UI). Max 65'535 characters!
		/// @return - The id of the newly created task
		std::string CreateTask(std::string const& taskName, std::string const& body);

		/// Create an Asana task with attachment
		/// @param taskName - Name of the new task
		/// @param attachmentBody - The content of the attachment
		/// @param attachmentFileName - The filename to pass in the HTTP request
		/// @param attachmentMimeType - The mime type to set in the HTTP request (Content-Type)
		/// @return - The id of the newly created task
		std::string CreateTaskWithAttachment(std::string const& taskName, std::vector<uint8_t> const& attachmentBody, std::string const& attachmentFileName, std::string const& attachmentMimeType);

		/// Get Asana tasks in a section
		/// @return - an array of quadruplets containing (1) the task id, (2) the task creation timestamp, (3) the data linked to this task and (4) if the data came from an attachment
		std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>, bool>> GetTasks();

		/// Delete task
		/// @param taskId - ID of the task to delete
		void DeleteTask(std::string const& taskId);

		/// Rename a task
		/// @param taskId - ID of the task
		/// @param newTaskName - The new name of the task
		void RenameTask(std::string const& taskId, std::string const& newTaskName);

		/// Add attachment to existing task
		/// @param taskId - ID of the task
		/// @param attachmentBody - The content of the attachment
		/// @param attachmentFileName - The filename to pass in the HTTP request
		/// @param attachmentMimeType - The mime type to set in the HTTP request (Content-Type)
		/// @return - the ID of the newly created attachment
		std::string AddAttachmentToTask(std::string const& taskId, std::vector<uint8_t> const& attachmentBody, std::string const& attachmentFileName, std::string const& attachmentMimeType);

		/// Retrieve the contents of an attachment
		/// @param attachmentId - The ID of the attachment to retrieve
		/// @return - The content of the attachment
		std::vector<uint8_t> GetAttachmentById(std::string const& attachmentId);
	private:
		/// Create or retrieve section by name
		/// @param sectionName - the name of the section to retrieve/create
		/// @return - the id of the section
		std::string GetOrCreateSectionIdByName(std::string const& sectionName);

		/// Retrieve sections of this project
		/// @param sectionName - the name of the section to retrieve
		/// @return - the id of the section (if found), or the empty string (if not found)
		std::string GetSectionIdByName(std::string const& sectionName);

		/// Create a section
		/// @param sectionName - the name of the section to retrieve
		/// @return - the id of the section
		std::string CreateSectionIdByName(std::string const& sectionName);

		/// Send http request, uses preset token for authentication (wrapper to easily set content type)
		FSecure::ByteVector FSecure::AsanaApi::SendHttpRequest(std::string const& host, WinHttp::ContentType contentType, std::vector<uint8_t> const& data, WinHttp::Method method, bool setAuthorizationHeader = true);

		/// Send http request, uses preset token for authentication
		FSecure::ByteVector FSecure::AsanaApi::SendHttpRequest(std::string const& host, std::wstring contentType, std::vector<uint8_t> const& data, WinHttp::Method method, bool setAuthorizationHeader = true);

		/// Send http request with json data, uses preset token for authentication
		json SendJsonRequest(std::string const& url, json const& data, WinHttp::Method method);

		/// Hold proxy settings
		WinHttp::WebProxy m_ProxyConfig;

		/// Holds the API token
		std::string m_Token;

		/// Holds the Project ID
		std::string m_ProjectId;

		/// Holds the Section ID for the inbound channel (auto-created or retrieved in constructor)
		std::string m_SectionIdInbound;

		/// Holds the Section ID for the outbound channel (auto-created or retrieved in constructor)
		std::string m_SectionIdOutbound;
	};
}