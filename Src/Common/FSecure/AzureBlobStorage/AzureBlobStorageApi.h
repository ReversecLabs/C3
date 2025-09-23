#pragma once

#include "Common/json/json.hpp"
#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/Constants.h"

using json = nlohmann::json; //for easy parsing of json API: https://github.com/nlohmann/json

namespace FSecure
{
	class AzureBlobStorage
	{
	public:

		/// Constructor for the AzureBlobStorage Api class.
		/// @param sasToken - the Shared Access Signature (SAS) token generated with full access to a container
		/// @param storageAccountName - the name of the Azure Storage Account
		/// @param containerName - the name of the container within Azure Blob Storage
		/// @param proxyString - the proxy to use
		AzureBlobStorage(std::string const& sasToken, std::string const& storageAccountName, std::string const& containerName, std::string const& channelName);

		/// Default constructor.
		AzureBlobStorage() = default;

		/// Write a message to the channel this AzureBlobStorage object is set to.
		/// @param text - the text of the message
		/// @return - a timestamp of the message that was written to the channel.
		void WriteMessageToFile(std::string const& direction, ByteView data, std::string const& providedFilename);

		/// Set the channel that this object uses for communications
		/// @param channel - the channelId (not name), for example CGPMGFGSH.
		void SetChannel(std::string const& channelId);

		/// set the token for this object.
		/// @param token - the textual api token.
		void SetToken(std::string const& token);

		/// Creates a channel on AzureBlobStorage, if the channel exists already, will call ListChannels internally to get the channelId.
		/// @param channelName - the actual name of the channel, such as "general".
		/// @return - the channelId of the new or already existing channel.
		std::string CreateChannel(std::string const& channelName);


		/// List all the channels in the workspace the object's token is tied to.
		/// @return - a map of {channelName -> channelId}
		std::map<std::string, std::string> ListChannels();

		std::vector<std::string> SplitBlobName(const std::string& blobName);

		/// Download file by its path.
		/// @param filename - path of file.
		/// @return - string of file content
		FSecure::ByteVector ReadFile(std::string const& filename);

		/// Delete a file
		/// @param filename - the full path of the file on Dropbox.
		void DeleteFile(std::string const& filename);

		/// Get all of the messages by a direction. This is a C3 specific method, used by a server relay to get client messages and vice versa.
		/// @param direction - the direction to search for (eg. "S2C").
		/// @return - a vector of timestamps, where timestamp allows replies to be read later
		std::map<std::string, std::string> GetMessagesByDirection(std::string const& direction);

		/// Upload a file in its entirety to Azure Blob Storage.
		/// @param path - path to file for upload
		void UploadFile(std::string const& path);


	private:

		/// The channel through which messages are sent and received, will be sent when the object is created.
		std::string m_Channel;

		/// The necessary parameters to retrieve access tokens for continued use. Needs to be manually created as described in documentation.
		std::string m_sasToken;
		std::string m_storageAccountName;
		std::string m_containerName;

		/// Hold proxy settings
		WinHttp::WebProxy m_ProxyConfig;

		/// Send http request, uses preset token for authentication
		FSecure::ByteVector FSecure::AzureBlobStorage::SendHttpRequest(std::string const& blobPath, WinHttp::ContentType contentType, WinHttp::Method method, std::string const& data = "");

		

	};

}
