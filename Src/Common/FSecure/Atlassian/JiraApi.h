#pragma once

#include "Common/json/json.hpp"
#include "Common/FSecure/WinHttp/HttpClient.h"
#include "Common/FSecure/WinHttp/WebProxy.h"
#include "Common/FSecure/WinHttp/Constants.h"

using json = nlohmann::json;

namespace FSecure
{
	class Jira
	{
	public:
		/// Constructor for the Jira API class.
		/// @param host - URL for JIRA instance, either local server or cloud instance (including port, no trailing '/')
		/// @param project_key - Key for project in which to create/use issue, e.g. 'TEST'
		/// @param issue_name - Summary name for the issue to lookup/create
		/// @param username - User for auth
		/// @param password - This could be the plaintext password or an API token if using cloud (https://id.atlassian.com/manage/api-tokens)
		Jira(std::string const& userAgent, std::string const& host, std::string const& project_key, std::string const& issue_name, std::string const& username, std::string const& password);

		/// Default constructor.
		Jira() = default;

		/// Write a comment on the issue
		/// @param message - data to write in comment
		/// @return - the comment ID
		std::string WriteCommentOnIssue(std::string const& message);

		/// Update an existing comment on the issue
		/// @param commentId - id of the comment to alter
		/// @param message - new contents of comment
		void UpdateCommentOnIssue(std::string const& commentId, std::string const& message);

		/// Upload a file in its entirety as an attachment to the issue.
		/// @param commentId - the id of the comment the attachment relates to, for mapping back to sequence.
		void UploadAttachment(ByteView data, std::string const& commentId);

		/// Set the channel (i.e. the Jira issue) that this object uses for communications
		/// @param channelId - the comment Id
		void SetChannel(std::string const& channelId);

		/// Create and set base64 auth header for this object.
		/// @param username - username (can be email address for cloud).
		/// @param password - plaintext password or API token
		void SetAuthToken(std::string const& username, std::string const& password);

		/// Will list the created issues in the Jira project and if already preset return the issue name. If not already created, 
		/// creates a new issue.
		/// @param issueName - the summary name of the issue to create, such as "Bug in front end".
		/// @return - the issue name of the new or already existing issue.
		std::string CreateIssue(std::string const& issueName);

		/// List all the issues in the project.
		/// @return - a map of {issueName -> issueId}
		std::map<std::string, std::string> ListIssues();

		/// Get all of the comments representing messages by a direction. This is a C3 specific method, used by a server relay to get client messages and vice versa.
		/// @param direction - the direction to search for (eg. "S2C").
		/// @return - a map of timestamp and comment id, where id allows edits/deletion later
		std::map<std::string, std::string> GetMessagesByDirection(std::string const& direction);

		/// Fetch all messages tied to a given comment Id
		/// @param id - id of the comment for which we want data
		/// @return - a tuple of [ comment/attachment id, content, object type comment/attachment ]
		std::vector<std::tuple<std::string, std::string, int>> ReadCommentReplies(std::string const& id);

		/// Delete a comment
		/// @param id - the id of the comment.
		void DeleteComment(std::string const& id);

		/// Delete an attachment
		/// @param id - the id of the attachment.
		void DeleteAttachment(std::string const& id);

		/// Delete the whole issue
		/// @param id - the id of the issue.
		void DeleteIssue();

	private:

		enum messageType { COMMENT, ATTACHMENT };


		/// The channel (i.e. issue) through which messages are sent and received, will be sent when the object is created.
		std::string m_issue;

		/// The necessary parameters to set the Jira host, target project, and means of auth.
		std::string m_host;
		std::string m_projectkey;
		std::string m_authtoken;

		/// Hold proxy settings
		WinHttp::WebProxy m_ProxyConfig;

		/// Create and send http request, uses preset token for authentication, with option to skip csrf check for attachment upload
		FSecure::ByteVector SendHttpRequest(FSecure::WinHttp::Method method, std::string const& host, std::wstring const& contentType = {}, std::vector<uint8_t> data = {}, bool xsrfCheck = true);

		/// Create initial request
		FSecure::WinHttp::HttpRequest CreateHttpRequest(FSecure::WinHttp::Method method, std::string const& host, std::wstring const& contentType = {}, std::vector<uint8_t> data = {}, bool xsrfCheck = true);

		/// Send http request with json data, uses preset token for authentication
		json SendJsonRequest(FSecure::WinHttp::Method method, std::string const& url, json const& data);

		/// The user agent header value.
		std::string m_UserAgent;

	};

}

