#pragma once

#include "Common/json/json.hpp"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/Constants.h"

using json = nlohmann::json; //for easy parsing of json API: https://github.com/nlohmann/json

namespace FSecure
{
	class GoogleDrive
	{
	public:

		/// Constructor for the GoogleDrive Api class. See quickstart.py for retrieving these values
		/// @param client_id - App url
		/// @param client_secret - Client secret
		/// @param refresh_token - the Outh refresh token for producing new access tokens
		/// @param proxyString - the proxy to use
		GoogleDrive(std::string const& userAgent, std::string const& client_id, std::string const& client_secret, std::string const& refresh_token, std::string const& channelName);

		/// Default constructor.
		GoogleDrive() = default;

		/// Write a message as the contents of a file and upload to Google Drive.
		/// @param direction - the name of the file to upload
		/// @param data - the text of the message
		/// @param filename - optional custom filename for uploaded file
		void WriteMessageToFile(std::string const& direction = "", ByteView data = {}, std::string const& providedFilename = "");

		/// Upload a file in its entirety to Google Drive.
		/// @param path - path to file for upload
		void UploadFile(std::string const& path);

		/// Delete channel folder and all files within
		void DeleteAllFiles();

		/// Set the channel (i.e. Google Drive folder) that this object uses for communications
		/// @param channelId - the channel Id (not name).
		void SetChannel(std::string const& channelId);

		/// Refresh the access token for this object.
		void RefreshAccessToken();

		/// set the access token for this object.
		/// @param token - the textual api token.
		void SetToken(std::string const& token);

		/// Will list the created folders in Google Drive and if already preset return the channel name. If not already created, 
		/// creates a new folder on Google Drive.
		/// @param channelName - the actual name of the folder to create, such as "files".
		/// @return - the channel name of the new or already existing channel.
		std::string CreateChannel(std::string const& channelName);

		/// List all the folders in the workspace the object's token is tied to.
		/// @return - a map of {channelName -> channelId}
		std::map<std::string, std::string> ListChannels();

		/// Get all of the files representing messages by a direction. This is a C3 specific method, used by a server relay to get client messages and vice versa.
		/// @param direction - the direction to search for (eg. "S2C").
		/// @return - a map of timestamp and file id, where id allows replies to be read later
		std::map<std::string, std::string> GetMessagesByDirection(std::string const& direction);

		/// Download file by its Google Drive resource id.
		/// @param id - id of file.
		/// @return - string of file content
		FSecure::ByteVector ReadFile(std::string const& id);

		/// Delete a file
		/// @param id - the id of the file on Google Drive.
		void DeleteFile(std::string const& id);

	private:

		/// The channel (i.e. folder) through which messages are sent and received, will be sent when the object is created.
		std::string m_Channel;

		/// The necessary parameters to retrieve access tokens for continued use. Needs to be manually created as described in documentation.
		std::string m_clientId;
		std::string m_clientSecret;
		std::string m_accessToken;
		std::string m_refreshToken;
		
		/// Hold proxy settings
		WinHttp::WebProxy m_ProxyConfig;

		/// Create and send http request, uses preset token for authentication
		FSecure::ByteVector SendHttpRequest(FSecure::WinHttp::Method method, std::string const& host, std::wstring const& contentType = {}, std::vector<uint8_t> data = {}, bool setAuthorizationHeader = true);

		/// Create initial request
		FSecure::WinHttp::HttpRequest CreateHttpRequest(FSecure::WinHttp::Method method, std::string const& host, std::wstring const& contentType = {}, std::vector<uint8_t> data = {}, bool setAuthorizationHeader = true);

		/// Send http request with json data, uses preset token for authentication
		json SendJsonRequest(FSecure::WinHttp::Method method, std::string const& url, json const& data);

		/// The user agent header value.
		std::string m_UserAgent;

	};

}

