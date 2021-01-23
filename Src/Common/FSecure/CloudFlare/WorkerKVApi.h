#pragma once

#include "Common/json/json.hpp"
#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/Constants.h"

using json = nlohmann::json; //for easy parsing of json API: https://github.com/nlohmann/json

namespace FSecure
{
	class WorkerKV
	{
	public:

		/// Constructor for the WorkerKV Api class.
		/// @param userAgent- User Agent we'll use for web requests
		/// @param accountId- ID for our CloudFlare account
		/// @param token - the API token generated within CloudFlare
		/// @param accountEmail - email associated with the CloudFlare account
		/// @param namespaceName - Namespace name under which all our key-values will be stored
		
		WorkerKV(std::string const& userAgent, std::string const& accountId, std::string const& token, std::string const& namespaceName);

		/// Default constructor.
		WorkerKV() = default;

		/// Write a message as the value of a key.
		/// @param direction - a prefix for the key to signify its direction
		/// @param data - the text of the message
		void WriteToKeyValue(std::string const& direction = "", std::string const& data = "");

		/// Delete namespace and all key values within
		void DeleteNamespace();

		/// Set the channel (i.e. WorkerKV namespace) that this object uses for communications
		/// @param namespaceId - the namespace Id (not the name).
		void SetNamespace(std::string const& namespaceId);

		/// set the token for this object.
		/// @param token - the textual api token.
		void SetToken(std::string const& token);

		/// Will list the created namespaces and if already preset return the namespace's Id. If not already created,
		/// creates a new namespace on WorkerKV.
		/// @param namespaceName - the actual name of the namespace to create, such as "files".
		/// @return - the namespace Id of the new or already existing channel.
		std::string CreateNamespace(std::string const& namespaceName);

		/// List all the namespaces in the account the object's token is tied to.
		/// @return - a map of {namespaceName -> namespaceId}
		std::map<std::string, std::string> ListNamespaces();

		/// Get all of the keys representing messages by a direction. This is a C3 specific method, used by a server relay to get client messages and vice versa.
		/// @param direction - the direction to search for (eg. "S2C").
		/// @return - a map of timestamp and key name, where key name allows us to be read later
		std::map<std::string, std::string> GetMessagesByDirection(std::string const& direction);

		/// Read value by key.
		/// @param keyname - name of the key.
		/// @return - string of key-value content
		std::string ReadKeyValue(std::string const& keyname);

		/// Delete a file
		/// @param filename - the full path of the file on WorkerKV.
		void DeleteKey(std::string const& keyname);

	private:

		/// The channel (i.e. namespace) through which messages are sent and received, will be sent when the object is created.
		std::string m_Namespace;

		/// The CloudFlare API token that allows the object access to the account. Needs to be manually created as described in documentation.
		std::string m_Token;

		/// The CloudFlare Account ID associated with the API token.
		std::string m_AccountId;

		/// Hold proxy settings
		WinHttp::WebProxy m_ProxyConfig;

		/// Send http request, uses preset token for authentication (wrapper to easily set content type)
		FSecure::ByteVector FSecure::WorkerKV::SendHttpRequest(std::string const& host, WinHttp::ContentType contentType, std::vector<uint8_t> const& data, WinHttp::Method method);

		/// Send http request, uses preset token for authentication
		FSecure::ByteVector FSecure::WorkerKV::SendHttpRequest(std::string const& host, std::wstring const& contentType, std::vector<uint8_t> const& data, WinHttp::Method method);

		/// Send http request
		FSecure::ByteVector SendHttpRequest(std::string const& host, std::string const& acceptType, FSecure::WinHttp::Method method);

		/// Send http request with json data, uses preset token for authentication
		json SendJsonRequest(std::string const& url, json const& data, WinHttp::Method method);

		/// The user agent header
		std::string m_UserAgent;

	};

}

