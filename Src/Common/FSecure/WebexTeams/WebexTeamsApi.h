#pragma once

#include <chrono>

#include "Common/json/json.hpp"
#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/Constants.h"
#include "Common/FSecure/Crypto/String.h"

using json = nlohmann::json;

namespace FSecure
{
	class WebexTeamsApi
	{
	public:

		/// Constructor for the WebexTeamsApi class.
		/// @param apiEndpoint - the URL of the API endpoint to use (webexapis.com or api.ciscospark.com)
		/// @param clientId - The Client ID of the OAuth application created in Webex Teams
		/// @param clientSecret - The Client Secret of the OAuth application created in Webex Teams
		/// @param userAgent - The User-Agent header to include in HTTP requests
		WebexTeamsApi(SecureString apiEndpoint, SecureString clientId, SecureString clientSecret, SecureString refreshToken, SecureString userAgent);

		/// Default constructor.
		WebexTeamsApi() = default;

		/// Requests new tokens using the refresh token
		/// @throws std::exception if tokens cannot be refreshed.
		void RefreshAccessToken();

		/// Post a message to a room
		/// @param text - the text of the message
		/// @param roomId - the roomId of the room to post the message in
		/// @return - the message id
		std::string WriteMessage(std::string const& text, std::string const& roomId);

		/// Post a message with an attachment to a room
		/// @param attachment - the content of the attachment
		/// @param roomId - the roomId of the room to post the message in
		/// @return - the message id
		std::string WriteMessageWithAttachment(ByteVector const& attachment, std::string const& attachmentFilename, std::string const& attachmentMimeType, std::string const& roomId);

		/// Retrieves messages in a room
		/// @param roomId - the roomId of the room to get messages from
		/// @return - an array of tuples containing the message id, message contents and a boolean indicating whether the content was retrieved from attachments or not. The array will be sorted (ascending) on message creation date.
		std::vector<std::tuple<std::string, ByteVector, bool>> GetMessages(std::string const& roomId);

		/// Creates a room
		/// @param roomName - the actual name of the room
		/// @return - the roomId of the new room.
		std::string CreateRoom(std::string const& roomName);

		/// List all the rooms
		/// @return - a map of {roomName -> roomId}
		std::map<std::string, std::string> ListRooms();

		/// Retrieves an existing room or creates a new room
		/// @param roomName - the name of the room
		/// @return - the roomId of the room
		std::string GetOrCreateRoom(std::string const& roomName);

		/// Delete a message
		/// @param messageId - the messageId of the message to delete
		void DeleteMessage(std::string const& messageId);

		/// Server will reject request send before s_TimePoint. This method will await to this point plus extra random delay.
		/// @param min lower limit of random delay.
		/// @param max upper limit of random delay.
		void RateLimitDelay(std::chrono::milliseconds min, std::chrono::milliseconds max);

		/// Update the refresh token
		/// @param newRefreshToken - the new refresh token to use
		void SetRefreshToken(SecureString newRefreshToken);

	private:
		/// Save access token from JSON response
		void SaveAccessToken(FSecure::json data); 

		/// Check if request was successful.
		/// @throws std::exception describing incorrect response if occurred.
		void EvaluateResponse(std::string const& host, WinHttp::Method method, WinHttp::HttpRequest const& req, WinHttp::HttpResponse const& resp, bool tryRefreshingToken = true);

		/// The roomId through which messages are sent and received
		Crypto::String m_RoomId;

		/// The Webex API endpoint
		Crypto::String m_ApiEndpoint;

		/// The Webex OAuth application ID and secret
		Crypto::String m_ClientId, m_ClientSecret;

		/// The Webex API tokens
		Crypto::String m_RefreshToken, m_AccessToken;

		/// Timestamp when the access token expires, and we should retrieve a new token before making any request
		int32_t m_AccessTokenExpiryTime;

		/// The User-Agent header
		Crypto::String m_UserAgent;

		/// Holds proxy settings
		WinHttp::WebProxy m_ProxyConfig;

		/// Used to delay every channel instance in case of server rate limit.
		/// Set using information from 429 Too Many Requests header.
		static std::atomic<std::chrono::steady_clock::time_point> s_TimePoint;

		/// Send http request, uses preset token for authentication
		ByteVector SendHttpRequest(std::string const& host, WinHttp::ContentType contentType, std::string const& data, WinHttp::Method, bool addAuthorizationHeader = true);

		/// Send http request, uses preset token for authentication
		ByteVector SendHttpRequest(std::string const& host, std::wstring const& contentType, std::vector<uint8_t> const& data, WinHttp::Method, bool addAuthorizationHeader = true);
	};

}
