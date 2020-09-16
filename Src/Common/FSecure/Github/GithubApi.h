#pragma once

#include "Common/json/json.hpp"
#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/Constants.h"

using json = nlohmann::json; //for easy parsing of json API: https://github.com/nlohmann/json

namespace FSecure
{
	class GithubApi
	{
	public:

		/// Constructor for the Github Api class.
		GithubApi(std::string const& token, std::string const& channelName, std::string const& userAgent);
		
		/// Retrieve the Github Username and initialise  for the instance
		void SetUser();

		/// set OAuth token for Github
		/// @param token - the textual Github OAuth token.
		void SetToken(std::string const& token);

		/// set UserAgent for Github HTTP Request
		/// @param userAgent
		void SetUserAgent(std::string const& userAgent);
		
		/// Set the channel (i.e. Github repository) that this object uses for communications
		/// @param channelName - the channel name Id (not name), for example CGPMGFGSH.
		void SetChannel(std::string const& channelName);

		/// Will list the created folders in Github and if already preset return the channel name. If not already created,
		/// creates a new folder on Github.
		/// @param channelName - the actual name of the folder to create, such as "files".
		/// @return - the channel name of the new or already existing channel.
		std::string CreateChannel(std::string const& channelName);

		/// List all the repository in the workspace the object's token is tied to.
		/// @return - a map of {channelName -> channelId}
		std::map<std::string, std::int64_t> ListChannels();

		/// Download file by its path.
		/// @param filename - path of file and the size. Format "filename:filesize"
		/// @return - string of file content
		FSecure::ByteVector ReadFile(std::string const& fileNameSHA);

		/// Write a message as the contents of a file and upload to Github.
		/// @param direction - the name of the file to upload
		/// @param data - the text of the message
		/// @param filename - optional custom filename for uploaded file
		void WriteMessageToFile(std::string const& direction = "", ByteView data = {}, std::string const& providedFilename = "");

		/// Upload a file in its entirety to Github
		/// @param path - path to file for upload
		void UploadFile(std::string const& path);

		/// Delete a file
		/// @param filename - the full path of the file on Github.
		void DeleteFile(std::string const& filename);

		/// Delete channel folder and all files within Github
		void DeleteAllFiles();

		/// Get all of the files representing messages by a direction. This is a C3 specific method, used by a server relay to get client messages and vice versa.
		/// @param direction - the direction to search for (eg. "S2C").
		/// @return - a map of timestamp and file id, where id allows replies to be read later
		std::map<std::string, std::string> GetMessagesByDirection(std::string const& direction);


		/// Default constructor.
		GithubApi() = default;

	private:

		/// Hold proxy settings
		WinHttp::WebProxy m_ProxyConfig;

		/// The Github username
		std::string m_Username;

		/// The Github channel (repo) through which messages are sent and received, will be sent when the object is created.
		std::string m_Channel;

		/// The Github OAuth Token that allows the object access to the account. Needs to be manually created as described in documentation.
		std::string m_Token;

		/// UserAgent 
		std::string m_UserAgent;



		/// Send http request, uses preset token for authentication (wrapper to easily set content type)
		FSecure::ByteVector FSecure::GithubApi::SendHttpRequest(std::string const& host, WinHttp::ContentType contentType, std::vector<uint8_t> const& data, WinHttp::Method method, bool setAuthorizationHeader = true);

		/// Send http request, uses preset token for authentication
		FSecure::ByteVector FSecure::GithubApi::SendHttpRequest(std::string const& host, std::wstring const& contentType, std::vector<uint8_t> const& data, WinHttp::Method method, bool setAuthorizationHeader = true);

		/// Send http request, uses preset token for authentication with github accept header to view raw file content
		FSecure::ByteVector SendHttpRequest(std::string const& host, std::string const& acceptType, FSecure::WinHttp::Method method, bool setAuthorizationHeader);

		/// Send http request with json data, uses preset token for authentication
		json SendJsonRequest(std::string const& url, json const& data, WinHttp::Method method);
	};

}

