#include <sql.h>
#include <sqltypes.h>
#include <sqlext.h>

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
						case SQL_HANDLE_ENV: return OBF_STR("ENV");
						case SQL_HANDLE_STMT: return OBF_STR("STMT");
						case SQL_HANDLE_DBC: return OBF_STR("DBC");
						case SQL_HANDLE_DESC: return OBF_STR("DESC");
						default: return ""s;
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
			Statement(SQLHANDLE connection, std::string statement) : m_Stmt{ Detail::MakeSqlHandle(SQL_HANDLE_STMT, connection) }, m_StmtString{ std::move(statement) }
			{
				if (m_StmtString.size() > std::numeric_limits<SQLINTEGER>::max())
					throw std::runtime_error{ OBF("Statement too long") };
			}

			void Execute()
			{
				SQLRETURN retCode = SQLExecDirectA(m_Stmt.get(), (SQLCHAR*)m_StmtString.c_str(), static_cast<SQLINTEGER>(m_StmtString.size()));
				if (retCode == SQL_ERROR)
					throw std::runtime_error{ OBF("Failed to execute statement: ") + m_StmtString.substr(0, 80) };
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
			Connection(SQLHANDLE env, std::string const& servername, std::string const& databasename, std::string const& username, std::string const& password, bool useSSPI, HANDLE impersonationToken) : m_Connection{ Detail::MakeSqlHandle(SQL_HANDLE_DBC, env) }
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
			Enviroment() : m_Env{ Detail::MakeSqlHandle(SQL_HANDLE_ENV) }
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
