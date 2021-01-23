#include "stdafx.h"
#include "WorkerKVApi.h"
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

FSecure::WorkerKV::WorkerKV(std::string const& userAgent, std::string const& accountId, std::string const& token, std::string const& namespaceName)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	this->m_Token = token;
	this->m_AccountId = accountId;
	this->m_UserAgent = userAgent;
	SetNamespace(CreateNamespace(Convert<Lowercase>(namespaceName)));
}

void FSecure::WorkerKV::SetNamespace(std::string const& namespaceId)
{
	this->m_Namespace = namespaceId;
}

void FSecure::WorkerKV::SetToken(std::string const& token)
{
	this->m_Token = token;
}

void FSecure::WorkerKV::WriteToKeyValue(std::string const& direction, std::string const& data)
{
	std::string keyname;

	///Create a key name thats prefixed with message direction and suffixed
	// with more granular timestamp for querying later
	std::string ts = std::to_string(FSecure::Utils::TimeSinceEpoch());
	keyname = direction + OBF("-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts;

	std::string url = OBF("https://api.cloudflare.com/client/v4/accounts/") + this->m_AccountId + OBF("/storage/kv/namespaces/") + this->m_Namespace + OBF("/values/") + keyname;

	SendHttpRequest(url, ContentType::Text, { data.begin(), data.end() }, Method::PUT);
}

void FSecure::WorkerKV::DeleteNamespace()
{
	std::string url = OBF("https://api.cloudflare.com/client/v4/accounts/") + this->m_AccountId + OBF("/storage/kv/namespaces/") + this->m_Namespace;
	SendHttpRequest(url, OBF("*/*"), Method::DEL);
}

std::map<std::string, std::string> FSecure::WorkerKV::ListNamespaces()
{
	std::map<std::string, std::string> NamespaceMap;	

	std::string url = OBF("https://api.cloudflare.com/client/v4/accounts/") + this->m_AccountId + OBF("/storage/kv/namespaces");
	
	json response = json::parse(SendHttpRequest(url, OBF("*/*"), Method::GET));

	for (auto& ns : response[OBF("result")])
	{
		NamespaceMap.emplace(ns[OBF("title")], ns[OBF("id")]);
	}

	return NamespaceMap;
}

std::string FSecure::WorkerKV::CreateNamespace(std::string const& namespaceName)
{
	std::map<std::string, std::string> namespaces = this->ListNamespaces();

	if (namespaces.find(namespaceName) == namespaces.end())
	{
		std::string url = OBF("https://api.cloudflare.com/client/v4/accounts/") + this->m_AccountId + OBF("/storage/kv/namespaces");

		json j;
		j[OBF("title")] = namespaceName;

		json response = SendJsonRequest(url, j, Method::POST);

		if (response[OBF("success")] != true)
			throw std::runtime_error(OBF("Throwing exception: unable to create channel\n"));
		
		return response[OBF("result")][OBF("id")];
	}
	return namespaces[namespaceName];
}

std::map<std::string, std::string> FSecure::WorkerKV::GetMessagesByDirection(std::string const& direction)
{
	std::map<std::string, std::string> messages;
	json response;
	std::string cursor;

	// Default behaviour is to retrieve 1000 results. 
	// As we're filtering by prefix too, it's very unlikely we'll hit paging limits but we should handle it
	do
	{
		if (cursor.empty())
		{
			std::string url = OBF("https://api.cloudflare.com/client/v4/accounts/") + this->m_AccountId + OBF("/storage/kv/namespaces/") + this->m_Namespace + OBF("/keys?prefix=") + direction;
			response = json::parse(SendHttpRequest(url, OBF("*/*"), Method::GET));
		}
		else
		{
			std::string url = OBF("https://api.cloudflare.com/client/v4/accounts/") + this->m_AccountId + OBF("/storage/kv/namespaces/") + this->m_Namespace + OBF("/keys?prefix=") + direction + OBF("&cursor=") + cursor;
			response = json::parse(SendHttpRequest(url, OBF("*/*"), Method::GET));
		}

		if (response[OBF("result_info")][OBF("cursor")].get<std::string>() != OBF(""))
			cursor = response[OBF("result_info")][OBF("cursor")];

		for (auto& match : response[OBF("result")])
		{
			std::string key_name = match[OBF("name")];
			std::string ts = key_name.substr(key_name.length() - 10); // 10 = epoch time length

			messages.insert({ ts, key_name });
		}
	} while (response[OBF("result_info")][OBF("cursor")].get<std::string>() != OBF(""));

	return messages;
}

std::string FSecure::WorkerKV::ReadKeyValue(std::string const& keyname)
{
	std::string url = OBF("https://api.cloudflare.com/client/v4/accounts/") + this->m_AccountId + OBF("/storage/kv/namespaces/") + this->m_Namespace + OBF("/values/") + keyname;
	auto resp = SendHttpRequest(url, OBF("*/*"), Method::GET);

	return { resp.begin(), resp.end() };
}

void FSecure::WorkerKV::DeleteKey(std::string const& keyname)
{
	std::string url = OBF("https://api.cloudflare.com/client/v4/accounts/") + this->m_AccountId + OBF("/storage/kv/namespaces/") + this->m_Namespace + OBF("/values/") + keyname;
	SendHttpRequest(url, OBF("*/*"), Method::DEL);
}

FSecure::ByteVector FSecure::WorkerKV::SendHttpRequest(std::string const& host, FSecure::WinHttp::ContentType contentType, std::vector<uint8_t> const& data, FSecure::WinHttp::Method method) {
	return SendHttpRequest(host, GetContentType(contentType), data, method);
}

FSecure::ByteVector FSecure::WorkerKV::SendHttpRequest(std::string const& host, std::wstring const& contentType, std::vector<uint8_t> const& data, FSecure::WinHttp::Method method) {
	while (true) {
		HttpClient webClient(ToWideString(host), m_ProxyConfig);
		HttpRequest request;
		request.m_Method = method;

		if (!data.empty()) {
			request.SetData(contentType, data);
		}

		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));
		request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_Token));
		
		auto resp = webClient.Request(request);

		if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Created) {
			return resp.GetData();
		}
		else if (resp.GetStatusCode() == StatusCode::TooManyRequests || resp.GetStatusCode() == StatusCode::Conflict) {
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		}
		else {
			throw std::exception(OBF("[x] Non 200/201/429 HTTP Response\n"));
		}
	}
}

FSecure::ByteVector FSecure::WorkerKV::SendHttpRequest(std::string const& host, std::string const& acceptType, FSecure::WinHttp::Method method) {
	while (true) {
		HttpClient webClient(ToWideString(host), m_ProxyConfig);
		HttpRequest request;
		request.m_Method = method;

		request.SetHeader(Header::Accept, ToWideString(acceptType));

		request.SetHeader(Header::UserAgent, ToWideString(this->m_UserAgent));
		request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_Token));

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

json FSecure::WorkerKV::SendJsonRequest(std::string const& url, json const& data, FSecure::WinHttp::Method method) {
	if (data == NULL) {
		return json::parse(SendHttpRequest(url, ContentType::MultipartFormData, {}, method));
	}
	else {
		std::string j = data.dump();
		return json::parse(SendHttpRequest(url, ContentType::ApplicationJson, { std::make_move_iterator(j.begin()), std::make_move_iterator(j.end()) }, method));
	}
}