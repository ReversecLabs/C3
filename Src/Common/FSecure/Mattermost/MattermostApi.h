#pragma once

#include "Common/json/json.hpp"
#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/Constants.h"

using json = nlohmann::json; //for easy parsing of json API: https://github.com/nlohmann/json

namespace FSecure
{
	class Mattermost
	{
	public:

		/// Constructor for the Mattermost Api class.
		/// @param serverUrl - the Mattermost server url with schema, without trailing slash, ex. https://my-mattermost.com
		/// @param accessToken - the Mattermost Personal Access Token value
		/// @param proxyString - the proxy to use
		Mattermost(std::string const& serverUrl, std::string const& teamName, std::string const& accessToken, std::string const& channelName, std::string const& userAgent);

		/// Default constructor.
		Mattermost() = default;

		/// Write a message to the channel this Mattermost object is set to.
		/// @param text - the text of the message
		/// @return - the post_id of post message created.
		std::string WritePost(std::string const& text, std::string const& fileID = "");

        /// Create a thread on a message by writing a reply to it.
        /// @param text - the text to send as a reply.
        /// @param timestamp - the timestamp of the message that the reply is for.
        /// @return - the post_id of reply message created.
        std::string WriteReply(std::string const& text, std::string const& postID, std::string const& fileID = "");


        void SetTeamID(std::string const& teamID);

        std::string FindTeamID(std::string const& teamName);

		/// Set the channel that this object uses for communications
		/// @param channel - the channelId (not name), for example CGPMGFGSH.
		void SetChannel(std::string const& channelId);

		/// set the token for this object.
		/// @param token - the textual api token.
		void SetToken(std::string const& accessToken);

		/// Creates a channel on Mattermost, if the channel exists already, will call ListChannels internally to get the channelId.
		/// @param channelName - the actual name of the channel, such as "general".
		/// @return - the channelId of the new or already existing channel.
		std::string CreateChannel(std::string const& channelName);

		/// Read the replies to a message
		/// @param timestamp - the timestamp of the original message, from which we can gather the replies.
		/// @return - an array of pairs containing the reply timestamp and reply text
		std::vector<std::pair<std::string, std::string>> ReadReplies(std::string const& postID);

		/// List all the channels in the workspace the object's token is tied to.
		/// @return - a map of {channelName -> channelId}
		std::map<std::string, std::string> ListChannels();

		/// Get all of the messages by a direction. This is a C3 specific method, used by a server relay to get client messages and vice versa.
		/// @param direction - the direction to search for (eg. "S2C").
		/// @return - a vector of timestamps, where timestamp allows replies to be read later
		std::vector<std::string> GetMessagesByDirection(std::string const& direction);

		/// Edit a previously sent message.
		/// @param message - the message to update to, this will overwrite the previous message.
		/// @param timestamp - the timestamp of the message to update.
		void UpdatePost(std::string const& message, std::string const& postID);


		/// Use Mattermost's file API to upload data as files. This is useful when a payload is large (for example during implant staging).
		/// This function is called internally whenever a WriteReply is called with a payload of more than 120k characters.
		/// @param data - the data to be sent.
		/// @param ts - the timestamp, needed as this method is only used during WriteReply.
		std::string UploadFile(ByteView data);

		/// Delete a message from the channel
		/// @param postID - the post_id of post message to delete.
		void DeletePost(std::string const& postID);

	private:

		std::string m_UserAgent;

		/// The Mattermost server URL
		std::string m_ServerUrl;

        /// The Team ID that contains/is to contain specified channel. Team is an analogy to Slack's Workspace.
        std::string m_TeamID;

		/// The channel through which messages are sent and received, will be sent when the object is created.
		std::string m_ChannelID;

		/// The Mattermost API token that allows the object access to the workspace. Needs to be manually created as described in documentation.
		std::string m_AccessToken;

		/// Hold proxy settings
		WinHttp::WebProxy m_ProxyConfig;

		std::string WritePostOrReply(std::string const& message, std::string const& postID = "", std::string const& fileID = "");

        /// Send http request, uses preset token for authentication
        ByteVector SendHttpRequest(std::string const& host, FSecure::WinHttp::Method method, std::optional<WinHttp::ContentType> contentType = {}, std::string const& data = "");
		ByteVector SendHttpRequest(std::string const& host, std::optional<WinHttp::ContentType> contentType = {}, std::string const& data = "");

		/// Send http request with json data, uses preset token for authentication
		json SendJsonRequest(std::string const& url, json const& data, FSecure::WinHttp::Method method = FSecure::WinHttp::Method::GET);

		/// Send http GET request, uses preset token for authentication, expect response of application/json type
		json GetJsonResponse(std::string const& url);

		/// Use Mattermost's File API to retrieve files.
		/// @param fileID - the id of previously uploaded file to retrieve.
		/// @return - the data within the file.
		std::string GetFile(std::string const& fileID);
	};

}
